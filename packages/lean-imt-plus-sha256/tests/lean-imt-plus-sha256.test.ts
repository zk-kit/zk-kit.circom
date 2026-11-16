import { assert } from "chai"
import { createHash } from "crypto"
import { Circomkit, WitnessTester } from "circomkit"
import {
    circomkit,
    MAX_DEPTH,
    proofAt,
    computeRoot,
    LeanIMTPlus,
    LeanIMTPlusHashFunctions,
    LeanIMTPlusProof
} from "./common"

const MASK_128 = (1n << 128n) - 1n
const MAX_256 = (1n << 256n) - 1n
// secq256r1 scalar field modulus.
const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn
// BN254 scalar field modulus.
const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

function toBE32(x: bigint): Uint8Array {
    const buf = new Uint8Array(32)
    let v = x
    for (let i = 31; i >= 0; i--) {
        buf[i] = Number(v & 0xffn)
        v >>= 8n
    }
    return buf
}

function digestToBigInt(digest: Buffer): bigint {
    return BigInt(`0x${digest.toString("hex")}`)
}

// SHA-256 over the concatenated 32-byte big-endian encodings.
function sha256Concat(...xs: bigint[]): bigint {
    const buf = new Uint8Array(32 * xs.length)
    xs.forEach((x, i) => buf.set(toBE32(x), 32 * i))
    return digestToBigInt(createHash("sha256").update(buf).digest())
}

const sha256Hash2 = (a: bigint, b: bigint) => sha256Concat(a, b)
const sha256LeafHash = (value: bigint, nextValue: bigint, tag: bigint) => sha256Concat(value, nextValue, tag)

function commitment(r: string): bigint {
    return digestToBigInt(createHash("sha256").update(r).digest())
}

function toLimbs(x: bigint): [bigint, bigint] {
    return [x >> 128n, x & MASK_128]
}

// Proof to circuit inputs as [hi, lo] limbs, padding siblings to MAX_DEPTH.
function toSha256Input(p: LeanIMTPlusProof<bigint>) {
    const siblings = [...p.siblings]
    while (siblings.length < MAX_DEPTH) siblings.push(0n)

    return {
        proofType: p.proofType,
        value: toLimbs(p.value),
        leafValue: toLimbs(p.leaf.value),
        leafNextValue: toLimbs(p.leaf.nextValue),
        leafIndex: p.leafIndex,
        depth: p.siblings.length,
        siblings: siblings.map(toLimbs)
    }
}

const hashes: LeanIMTPlusHashFunctions<bigint> = {
    leaf: sha256LeafHash,
    internal: sha256Hash2
}

const PRIMES = [
    ["secq256r1", P256_P],
    ["bn128", BN254_R]
] as const

for (const [prime, fieldModulus] of PRIMES) {
    describe(`lean-imt-plus-sha256 (${prime})`, () => {
        let circuit: WitnessTester<
            ["proofType", "value", "leafValue", "leafNextValue", "leafIndex", "depth", "siblings"],
            ["out"]
        >
        let tree: LeanIMTPlus<bigint>
        const values = ["a", "b", "c", "d", "e", "f"].map(commitment)
        const [c0, c1, , , , c5] = values

        before(async () => {
            const kit =
                prime === "bn128"
                    ? circomkit
                    : new Circomkit({ ...circomkit.config, prime, dirBuild: `./build/${prime}` })

            circuit = await kit.WitnessTester(`lean-imt-plus-sha256-${prime}`, {
                file: "lean-imt-plus-sha256",
                template: "LeanIMTPlusSha256",
                params: [MAX_DEPTH]
            })

            tree = new LeanIMTPlus<bigint>(hashes)
            tree.insertMany(values)
        })

        it("verifies a membership proof and outputs the correct root", async () => {
            const proof = tree.generateProof(c1)
            assert.equal(proof.proofType, 0)
            await circuit.expectPass(toSha256Input(proof), { out: toLimbs(tree.root) })
        })

        it("verifies a membership proof for a promoted (unpaired) leaf", async () => {
            // 7 leaves: index 6 has no right sibling, so its path skips a level.
            const proof = tree.generateProof(c5)
            assert.equal(proof.siblings.length, 2)
            assert.equal(proof.leafIndex, 3)
            await circuit.expectPass(toSha256Input(proof), { out: toLimbs(tree.root) })
        })

        it("verifies a non-membership proof for a value strictly between two leaves", async () => {
            const sorted = [...values].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
            const between = sorted[2] + 1n
            const proof = tree.generateProof(between)
            assert.equal(proof.proofType, 1)
            assert.equal(proof.leaf.value, sorted[2])
            await circuit.expectPass(toSha256Input(proof), { out: toLimbs(tree.root) })
        })

        it("verifies a non-membership proof using the sentinel as low leaf", async () => {
            const proof = tree.generateProof(1n)
            assert.equal(proof.proofType, 1)
            assert.equal(proof.leaf.value, 0n)
            await circuit.expectPass(toSha256Input(proof), { out: toLimbs(tree.root) })
        })

        it("verifies a non-membership proof using the tail as low leaf", async () => {
            const proof = tree.generateProof(MAX_256)
            assert.equal(proof.proofType, 1)
            assert.equal(proof.leaf.nextValue, 0n)
            await circuit.expectPass(toSha256Input(proof), { out: toLimbs(tree.root) })
        })

        it("verifies a non-membership proof for a value that was previously removed", async () => {
            const t = new LeanIMTPlus<bigint>(hashes)
            t.insertMany(values)
            t.remove(c1)
            const proof = t.generateProof(c1)
            assert.equal(proof.proofType, 1)
            await circuit.expectPass(toSha256Input(proof), { out: toLimbs(t.root) })
        })

        it("verifies proofs for values at or above the secq256r1 modulus", async () => {
            const t = new LeanIMTPlus<bigint>(hashes)
            t.insertMany([10n, P256_P, MAX_256])

            for (const v of [P256_P, MAX_256]) {
                const proof = t.generateProof(v)
                assert.equal(proof.proofType, 0)
                await circuit.expectPass(toSha256Input(proof), { out: toLimbs(t.root) })
            }

            const proof = t.generateProof(P256_P + 1n)
            assert.equal(proof.proofType, 1)
            await circuit.expectPass(toSha256Input(proof), { out: toLimbs(t.root) })
        })

        it("verifies a non-membership proof when values differ only in the low limb", async () => {
            const hi = 7n << 128n
            const t = new LeanIMTPlus<bigint>(hashes)
            t.insertMany([hi + 5n, hi + 9n])
            const proof = t.generateProof(hi + 7n)
            assert.equal(proof.proofType, 1)
            assert.equal(proof.leaf.value, hi + 5n)
            await circuit.expectPass(toSha256Input(proof), { out: toLimbs(t.root) })
        })

        it("rejects a membership proof whose leafValue does not equal value", async () => {
            const proof = tree.generateProof(c1)
            await circuit.expectFail({ ...toSha256Input(proof), value: toLimbs(c1 + 1n) })
        })

        it("rejects a membership proof whose value differs only in the high limb", async () => {
            const proof = tree.generateProof(c1)
            await circuit.expectFail({ ...toSha256Input(proof), value: toLimbs(c1 ^ (1n << 200n)) })
        })

        it("rejects a non-membership proof claiming an actual member is absent", async () => {
            const proof = tree.generateProof(1n)
            const smallest = values.reduce((a, b) => (a < b ? a : b))
            await circuit.expectFail({ ...toSha256Input(proof), value: toLimbs(smallest) })
        })

        it("rejects a flipped proofType", async () => {
            const proof = tree.generateProof(c0)
            await circuit.expectFail({ ...toSha256Input(proof), proofType: 1 })
        })

        it("rejects a non-boolean proofType", async () => {
            const proof = tree.generateProof(c1)
            await circuit.expectFail({ ...toSha256Input(proof), proofType: 2 })
        })

        it("rejects membership of the zero value using the sentinel leaf", async () => {
            // The sentinel's real path (leafIndex 0); only the zero-value guard rejects it.
            const proof = tree.generateProof(1n)
            assert.equal(proof.leaf.value, 0n)
            await circuit.expectFail({ ...toSha256Input(proof), proofType: 0, value: [0n, 0n] })
        })

        it("rejects a depth greater than MAX_DEPTH", async () => {
            const proof = tree.generateProof(c1)
            await circuit.expectFail({ ...toSha256Input(proof), depth: MAX_DEPTH + 1 })
        })

        it("rejects a fake leaf hidden inside an inserted value's leaf", async () => {
            // Regression for the old 216-bit scheme, where leaf = H(H(v, n), 1): inserting
            // v* = H(H(1, 0), 1) let a prover claim a fake tail leaf {1, 0} two levels below
            // v*'s real leaf. Leaves now hash 96 bytes and internal nodes 64, so this
            // forgery would need a SHA-256 collision; the test guards against reverting
            // to a nested leaf hash.
            const vStar = sha256Hash2(sha256Hash2(1n, 0n), 1n)
            const t = new LeanIMTPlus<bigint>(hashes)
            t.insertMany([...values.slice(0, 3), vStar])
            const real = t.generateProof(vStar)
            const siblings = [real.leaf.nextValue, 1n, ...real.siblings]
            while (siblings.length < MAX_DEPTH) siblings.push(0n)

            const forged = {
                proofType: 1,
                value: toLimbs(c0),
                leafValue: toLimbs(1n),
                leafNextValue: toLimbs(0n),
                leafIndex: real.leafIndex << 2,
                depth: real.siblings.length + 2,
                siblings: siblings.map(toLimbs)
            }
            // Control: the real proof yields the true root.
            assert.deepEqual(await circuit.compute(toSha256Input(real), ["out"]), { out: toLimbs(t.root) })
            const { out } = await circuit.compute(forged, ["out"])
            assert.notDeepEqual(out, toLimbs(t.root))
        })

        it("rejects a value limb that is out of range (>= 2^128)", async () => {
            const proof = tree.generateProof(c5)
            const [hi, lo] = toLimbs(c5)
            // Same integer, non-canonically split across the limbs.
            await circuit.expectFail({ ...toSha256Input(proof), value: [hi - 1n, lo + (1n << 128n)] })
        })

        it("rejects a sibling limb that is out of range (>= 2^128)", async () => {
            const proof = tree.generateProof(c1)
            const input = toSha256Input(proof)
            const [hi, lo] = input.siblings[0]
            input.siblings[0] = [hi - 1n, lo + (1n << 128n)]
            await circuit.expectFail(input)
        })

        it("rejects a non-canonical leafIndex (high bit set past depth)", async () => {
            const proof = tree.generateProof(c1)
            const nonCanonical = proof.leafIndex | (1 << proof.siblings.length)
            await circuit.expectFail({ ...toSha256Input(proof), leafIndex: nonCanonical })
        })

        it("rejects a non-membership proof whose low leaf is a tombstone", async () => {
            const sorted = [...values].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
            const proof = tree.generateProof(sorted[2] + 1n)
            await circuit.expectFail({ ...toSha256Input(proof), leafValue: [0n, 0n], leafNextValue: [0n, 0n] })
        })

        it("verifies a membership proof after an update", async () => {
            const t = new LeanIMTPlus<bigint>(hashes)
            t.insertMany(values)
            const updated = commitment("updated")
            t.update(c1, updated)
            const proof = t.generateProof(updated)
            assert.equal(proof.proofType, 0)
            await circuit.expectPass(toSha256Input(proof), { out: toLimbs(t.root) })
        })

        it("verifies proofs at depth == MAX_DEPTH", async () => {
            const t = new LeanIMTPlus<bigint>(hashes)
            const many = Array.from({ length: 600 }, (_, i) => commitment(`v${i}`))
            t.insertMany(many)
            assert.equal(t.depth, MAX_DEPTH)

            const membership = t.generateProof(many[300])
            assert.equal(membership.siblings.length, MAX_DEPTH)
            await circuit.expectPass(toSha256Input(membership), { out: toLimbs(t.root) })

            const nonMembership = t.generateProof(many[300] + 1n)
            assert.equal(nonMembership.proofType, 1)
            await circuit.expectPass(toSha256Input(nonMembership), { out: toLimbs(t.root) })
        })

        it("verifies a proof at depth 0 (the root is the leaf commitment)", async () => {
            const input = {
                proofType: 0,
                value: toLimbs(c0),
                leafValue: toLimbs(c0),
                leafNextValue: [0n, 0n],
                leafIndex: 0,
                depth: 0,
                siblings: Array(MAX_DEPTH).fill([0n, 0n])
            }
            await circuit.expectPass(input, { out: toLimbs(sha256LeafHash(c0, 0n, 1n)) })
        })

        it("verifies a non-membership proof against an emptied tree", async () => {
            // Removing the only value leaves the sentinel as {0, 0} at index 0.
            const t = new LeanIMTPlus<bigint>(hashes)
            t.insert(c0)
            t.remove(c0)
            const proof = t.generateProof(c0)
            assert.equal(proof.leafIndex, 0)
            assert.deepEqual(proof.leaf, { value: 0n, nextValue: 0n })
            await circuit.expectPass(toSha256Input(proof), { out: toLimbs(t.root) })
        })

        it("rejects a non-membership proof using a real tombstoned slot as low leaf", async () => {
            const t = new LeanIMTPlus<bigint>(hashes)
            t.insertMany(values)
            const slot = t.indexOf(c1)
            t.remove(c1)
            // The tombstone's genuine path reaches the real root; only the guard rejects it.
            const proof = proofAt(t, slot, 1, c1)
            assert.deepEqual(proof.leaf, { value: 0n, nextValue: 0n })
            assert.equal(computeRoot(proof, hashes), t.root)
            await circuit.expectFail(toSha256Input(proof))
        })

        it("rejects a non-membership proof where value equals leafNextValue", async () => {
            const proof = tree.generateProof(c1 + 1n)
            assert.notEqual(proof.leaf.nextValue, 0n)
            await circuit.expectFail({ ...toSha256Input(proof), value: toLimbs(proof.leaf.nextValue) })
        })

        it("rejects a non-membership proof where value equals leafValue", async () => {
            const proof = tree.generateProof(c1 + 1n)
            await circuit.expectFail({ ...toSha256Input(proof), value: toLimbs(proof.leaf.value) })
        })

        it("outputs a different root when a sibling is tampered with", async () => {
            const input = toSha256Input(tree.generateProof(c1))
            assert.deepEqual(await circuit.compute(input, ["out"]), { out: toLimbs(tree.root) })
            input.siblings[0] = [input.siblings[0][0], input.siblings[0][1] ^ 1n]
            const { out } = await circuit.compute(input, ["out"])
            assert.notDeepEqual(out, toLimbs(tree.root))
        })

        it("rejects a leafIndex that does not fit in MAX_DEPTH bits", async () => {
            const proof = tree.generateProof(c1)
            await circuit.expectFail({ ...toSha256Input(proof), leafIndex: 1 << MAX_DEPTH })
        })

        it("rejects a depth that wraps around the field (p - 1)", async () => {
            const proof = tree.generateProof(c1)
            await circuit.expectFail({ ...toSha256Input(proof), depth: fieldModulus - 1n })
        })

        it("rejects out-of-range leafValue and leafNextValue limbs (>= 2^128)", async () => {
            const proof = tree.generateProof(c1 + 1n)
            const input = toSha256Input(proof)
            const [vHi, vLo] = input.leafValue
            const [nHi, nLo] = input.leafNextValue
            await circuit.expectFail({ ...input, leafValue: [vHi - 1n, vLo + (1n << 128n)] })
            await circuit.expectFail({ ...input, leafNextValue: [nHi - 1n, nLo + (1n << 128n)] })
        })

        it("rejects a non-canonically split value in a non-membership proof", async () => {
            // Chosen so only the value range check can fail: the high limbs alone decide
            // both comparisons and every LessThan(128) stays in range.
            const low = (5n << 128n) + 100n
            const high = (9n << 128n) + 100n
            const target = (7n << 128n) + 50n
            const t = new LeanIMTPlus<bigint>(hashes)
            t.insertMany([low, high])
            const proof = t.generateProof(target)
            assert.equal(proof.leaf.value, low)
            await circuit.expectPass(toSha256Input(proof), { out: toLimbs(t.root) })
            await circuit.expectFail({ ...toSha256Input(proof), value: [6n, 50n + (1n << 128n)] })
        })
    })
}
