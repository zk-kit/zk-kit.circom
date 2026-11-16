import { assert } from "chai"
import { poseidon2, poseidon3 } from "poseidon-lite"
import { WitnessTester } from "circomkit"
import { circomkit, MAX_DEPTH, toInput, proofAt, computeRoot, LeanIMTPlus, LeanIMTPlusHashFunctions } from "./common"

// BN254 scalar field modulus.
const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

const hashes: LeanIMTPlusHashFunctions<bigint> = {
    leaf: (a, b, c) => poseidon3([a, b, c]),
    internal: (a, b) => poseidon2([a, b])
}

describe("lean-imt-plus", () => {
    let circuit: WitnessTester<
        ["proofType", "value", "leafValue", "leafNextValue", "leafIndex", "depth", "siblings"],
        ["out"]
    >
    let tree: LeanIMTPlus<bigint>

    before(async () => {
        circuit = await circomkit.WitnessTester("lean-imt-plus", {
            file: "lean-imt-plus",
            template: "LeanIMTPlus",
            params: [MAX_DEPTH]
        })

        tree = new LeanIMTPlus<bigint>(hashes)
        tree.insertMany([10n, 25n, 7n, 3n, 41n, 18n])
    })

    it("verifies a membership proof and outputs the correct root", async () => {
        const proof = tree.generateProof(25n)
        assert.equal(proof.proofType, 0)
        await circuit.expectPass(toInput(proof), { out: tree.root })
    })

    it("verifies a non-membership proof for a value strictly between two leaves", async () => {
        const proof = tree.generateProof(20n)
        assert.equal(proof.proofType, 1)
        await circuit.expectPass(toInput(proof), { out: tree.root })
    })

    it("verifies a non-membership proof using the sentinel as low leaf", async () => {
        const proof = tree.generateProof(1n)
        assert.equal(proof.proofType, 1)
        assert.equal(proof.leaf.value, 0n)
        await circuit.expectPass(toInput(proof), { out: tree.root })
    })

    it("verifies a non-membership proof using the tail as low leaf", async () => {
        const proof = tree.generateProof(100n)
        assert.equal(proof.proofType, 1)
        assert.equal(proof.leaf.nextValue, 0n)
        await circuit.expectPass(toInput(proof), { out: tree.root })
    })

    it("verifies a membership proof after an update", async () => {
        const t = new LeanIMTPlus<bigint>(hashes)
        t.insertMany([10n, 25n, 7n, 3n, 41n, 18n])
        t.update(25n, 22n)
        const proof = t.generateProof(22n)
        assert.equal(proof.proofType, 0)
        await circuit.expectPass(toInput(proof), { out: t.root })
    })

    it("verifies a non-membership proof for a value that was previously removed", async () => {
        const t = new LeanIMTPlus<bigint>(hashes)
        t.insertMany([10n, 25n, 7n, 3n, 41n, 18n])
        t.remove(25n)
        const proof = t.generateProof(25n)
        assert.equal(proof.proofType, 1)
        await circuit.expectPass(toInput(proof), { out: t.root })
    })

    it("rejects a membership proof whose leafValue does not equal value", async () => {
        const proof = tree.generateProof(25n)
        await circuit.expectFail({ ...toInput(proof), value: 26n })
    })

    it("rejects a non-membership proof claiming an actual member is absent", async () => {
        const proof = tree.generateProof(20n)
        await circuit.expectFail({ ...toInput(proof), value: 18n })
    })

    it("rejects a flipped proofType", async () => {
        const proof = tree.generateProof(10n)
        await circuit.expectFail({ ...toInput(proof), proofType: 1 })
    })

    it("rejects a non-boolean proofType", async () => {
        const proof = tree.generateProof(25n)
        await circuit.expectFail({ ...toInput(proof), proofType: 2 })
    })

    it("rejects membership of the zero value using the sentinel leaf", async () => {
        // The sentinel's real path (leafIndex 0); only the zero-value guard rejects it.
        const proof = tree.generateProof(1n)
        assert.equal(proof.leaf.value, 0n)
        await circuit.expectFail({ ...toInput(proof), proofType: 0, value: 0n })
    })

    it("rejects a non-membership proof for an out-of-range value (>= 2^252)", async () => {
        const proof = tree.generateProof(100n)
        assert.equal(proof.leaf.nextValue, 0n)
        await circuit.expectFail({ ...toInput(proof), value: (1n << 252n) + 1n })
    })

    it("rejects a non-canonical leafIndex (high bit set past depth)", async () => {
        const proof = tree.generateProof(25n)
        // Same position, non-canonical encoding.
        const nonCanonical = proof.leafIndex | (1 << proof.siblings.length)
        await circuit.expectFail({ ...toInput(proof), leafIndex: nonCanonical })
    })

    it("rejects a depth greater than MAX_DEPTH", async () => {
        const proof = tree.generateProof(25n)
        await circuit.expectFail({ ...toInput(proof), depth: MAX_DEPTH + 1 })
    })

    it("rejects a non-membership proof whose low leaf is a tombstone (zero value at non-zero index)", async () => {
        const proof = tree.generateProof(20n)
        // Tombstone shape {0, 0} at a non-zero index.
        await circuit.expectFail({ ...toInput(proof), leafValue: 0n, leafNextValue: 0n })
    })

    it("verifies a membership proof for a promoted (unpaired) leaf", async () => {
        // 7 leaves: index 6 has no right sibling, so its path skips a level.
        const proof = tree.generateProof(18n)
        assert.equal(proof.siblings.length, 2)
        assert.equal(proof.leafIndex, 3)
        await circuit.expectPass(toInput(proof), { out: tree.root })
    })

    it("verifies proofs at depth == MAX_DEPTH", async () => {
        const t = new LeanIMTPlus<bigint>(hashes)
        t.insertMany(Array.from({ length: 600 }, (_, i) => BigInt(2 * i + 2)))
        assert.equal(t.depth, MAX_DEPTH)

        const membership = t.generateProof(500n)
        assert.equal(membership.siblings.length, MAX_DEPTH)
        await circuit.expectPass(toInput(membership), { out: t.root })

        const nonMembership = t.generateProof(501n)
        assert.equal(nonMembership.proofType, 1)
        await circuit.expectPass(toInput(nonMembership), { out: t.root })
    })

    it("verifies a proof at depth 0 (the root is the leaf commitment)", async () => {
        const input = {
            proofType: 0,
            value: 5n,
            leafValue: 5n,
            leafNextValue: 0n,
            leafIndex: 0,
            depth: 0,
            siblings: Array(MAX_DEPTH).fill(0n)
        }
        await circuit.expectPass(input, { out: poseidon3([5n, 0n, 1n]) })
    })

    it("verifies a non-membership proof against an emptied tree", async () => {
        // Removing the only value leaves the sentinel as {0, 0} at index 0.
        const t = new LeanIMTPlus<bigint>(hashes)
        t.insert(10n)
        t.remove(10n)
        const proof = t.generateProof(10n)
        assert.equal(proof.leafIndex, 0)
        assert.deepEqual(proof.leaf, { value: 0n, nextValue: 0n })
        await circuit.expectPass(toInput(proof), { out: t.root })
    })

    it("rejects a non-membership proof using a real tombstoned slot as low leaf", async () => {
        const t = new LeanIMTPlus<bigint>(hashes)
        t.insertMany([10n, 25n, 7n, 3n, 41n, 18n])
        const slot = t.indexOf(25n)
        t.remove(25n)
        // The tombstone's genuine path reaches the real root; only the guard rejects it.
        const proof = proofAt(t, slot, 1, 26n)
        assert.deepEqual(proof.leaf, { value: 0n, nextValue: 0n })
        assert.equal(computeRoot(proof, hashes), t.root)
        await circuit.expectFail(toInput(proof))
    })

    it("rejects a non-membership proof where value equals leafNextValue", async () => {
        const proof = tree.generateProof(20n)
        await circuit.expectFail({ ...toInput(proof), value: proof.leaf.nextValue })
    })

    it("rejects a non-membership proof where value equals leafValue", async () => {
        const proof = tree.generateProof(20n)
        await circuit.expectFail({ ...toInput(proof), value: proof.leaf.value })
    })

    it("outputs a different root when a sibling is tampered with", async () => {
        const proof = tree.generateProof(25n)
        const input = toInput(proof)
        assert.deepEqual(await circuit.compute(input, ["out"]), { out: tree.root })
        input.siblings[0] += 1n
        const { out } = await circuit.compute(input, ["out"])
        assert.notEqual(out, tree.root)
    })

    it("rejects a leafIndex that does not fit in MAX_DEPTH bits", async () => {
        const proof = tree.generateProof(25n)
        await circuit.expectFail({ ...toInput(proof), leafIndex: 1 << MAX_DEPTH })
    })

    it("rejects a depth that wraps around the field (p - 1)", async () => {
        const proof = tree.generateProof(25n)
        await circuit.expectFail({ ...toInput(proof), depth: BN254_R - 1n })
    })

    it("rejects a wrapped-around low leaf (leafValue >= 2^252) hiding a member", async () => {
        // A stored value of p - 1 sorts last, but LessThan(252) would treat it as -1 < 10.
        const t = new LeanIMTPlus<bigint>(hashes)
        t.insertMany([10n, 20n, BN254_R - 1n])
        const proof = proofAt(t, t.indexOf(BN254_R - 1n), 1, 10n)
        assert.equal(computeRoot(proof, hashes), t.root)
        await circuit.expectFail(toInput(proof))
    })

    it("rejects a membership proof whose leafNextValue is out of range (>= 2^252)", async () => {
        const t = new LeanIMTPlus<bigint>(hashes)
        t.insertMany([10n, 1n << 252n])
        const proof = t.generateProof(10n)
        assert.equal(proof.leaf.nextValue, 1n << 252n)
        await circuit.expectFail(toInput(proof))
    })
})
