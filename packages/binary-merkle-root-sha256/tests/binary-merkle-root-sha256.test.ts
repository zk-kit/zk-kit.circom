import { strict as assert } from "assert"
import { Circomkit, WitnessTester } from "circomkit"
import { circomkit, commitment, generateBinaryMerkleRoot, sha256Hash2, toInput, toLimbs } from "./common"

const MAX_DEPTH = 5

// secq256r1 scalar field modulus.
const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn
// BN254 scalar field modulus.
const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

const PRIMES = [
    ["bn128", BN254_R],
    ["secq256r1", P256_P]
] as const

for (const [prime, fieldModulus] of PRIMES) {
    describe(`binary-merkle-root-sha256 (${prime})`, () => {
        let circuit: WitnessTester<["leaf", "depth", "index", "siblings"], ["out"]>

        before(async () => {
            const kit =
                prime === "bn128"
                    ? circomkit
                    : new Circomkit({ ...circomkit.config, prime, dirBuild: `./build/${prime}` })

            circuit = await kit.WitnessTester(`binary-merkle-root-sha256-${prime}`, {
                file: "binary-merkle-root-sha256",
                template: "BinaryMerkleRootSha256",
                params: [MAX_DEPTH]
            })
        })

        it("Should throw an error if there are not enough values for input signal siblings", async () => {
            await circuit.expectFail({
                leaf: [0n, 0n],
                depth: MAX_DEPTH,
                index: 0,
                siblings: []
            })
        })

        it("Should throw an error if there are too many values for input signal siblings", async () => {
            const proof = generateBinaryMerkleRoot(MAX_DEPTH, 2 ** MAX_DEPTH + 1)

            await circuit.expectFail(toInput(proof))
        })

        it("Should calculate the root correctly if the depth is less than MAX_DEPTH", async () => {
            const proof = generateBinaryMerkleRoot(MAX_DEPTH, 2 ** (MAX_DEPTH - 2))

            await circuit.expectPass(toInput(proof), { out: toLimbs(proof.root) })
        })

        it("Should calculate the root correctly if the depth equals MAX_DEPTH", async () => {
            const proof = generateBinaryMerkleRoot(MAX_DEPTH, 2 ** MAX_DEPTH, 21)

            await circuit.expectPass(toInput(proof), { out: toLimbs(proof.root) })
        })

        it("Should calculate the root correctly at depth 0 (the root is the leaf)", async () => {
            // Single leaf: root == leaf.
            const leaf = commitment("0")
            const proof = { leaf, depth: 0, index: 0, siblings: Array(MAX_DEPTH).fill(0n), root: leaf }

            await circuit.expectPass(toInput(proof), { out: toLimbs(proof.root) })
        })

        it("Should calculate the root correctly for every leaf of a non-full tree", async () => {
            const nodes = 11

            for (let leafIndex = 0; leafIndex < nodes; leafIndex += 1) {
                const proof = generateBinaryMerkleRoot(MAX_DEPTH, nodes, leafIndex)

                await circuit.expectPass(toInput(proof), { out: toLimbs(proof.root) })
            }
        })

        it("Should calculate the root correctly for 256-bit values at or above the secq256r1 modulus", async () => {
            const leaf = P256_P + 1n
            const sibling = (1n << 256n) - 1n
            const proof = {
                leaf,
                depth: 1,
                index: 1,
                siblings: [sibling, 0n, 0n, 0n, 0n],
                root: sha256Hash2(sibling, leaf)
            }

            await circuit.expectPass(toInput(proof), { out: toLimbs(proof.root) })
        })

        it("Should not output the tree root if the leaf is changed", async () => {
            const proof = generateBinaryMerkleRoot(MAX_DEPTH, 2 ** MAX_DEPTH, 3)

            await assert.rejects(
                circuit.expectPass(toInput({ ...proof, leaf: commitment("x") }), { out: toLimbs(proof.root) })
            )
        })

        it("Should not output the tree root if a sibling is changed", async () => {
            const proof = generateBinaryMerkleRoot(MAX_DEPTH, 2 ** MAX_DEPTH, 3)
            const siblings = [...proof.siblings]
            siblings[2] ^= 1n

            await assert.rejects(circuit.expectPass(toInput({ ...proof, siblings }), { out: toLimbs(proof.root) }))
        })

        it("Should throw an error if the depth is greater than MAX_DEPTH", async () => {
            const proof = generateBinaryMerkleRoot(MAX_DEPTH, 2 ** MAX_DEPTH)

            await circuit.expectFail(toInput({ ...proof, depth: MAX_DEPTH + 1 }))
        })

        it("Should throw an error if the depth wraps around the field (p - 1)", async () => {
            const proof = generateBinaryMerkleRoot(MAX_DEPTH, 2 ** MAX_DEPTH)

            await circuit.expectFail({ ...toInput(proof), depth: fieldModulus - 1n })
        })

        it("Should throw an error if the index does not fit in MAX_DEPTH bits", async () => {
            const proof = generateBinaryMerkleRoot(MAX_DEPTH, 2 ** MAX_DEPTH)

            await circuit.expectFail({ ...toInput(proof), index: 2 ** MAX_DEPTH })
        })

        it("Should throw an error if a leaf limb is out of range (>= 2^128)", async () => {
            const proof = generateBinaryMerkleRoot(MAX_DEPTH, 2 ** MAX_DEPTH)
            const [hi, lo] = toLimbs(proof.leaf)

            // Same value, non-canonical split.
            await circuit.expectFail({ ...toInput(proof), leaf: [hi - 1n, lo + (1n << 128n)] })
        })

        it("Should throw an error if a sibling limb is out of range (>= 2^128)", async () => {
            const proof = generateBinaryMerkleRoot(MAX_DEPTH, 2 ** MAX_DEPTH)
            const input = toInput(proof)
            input.siblings[0] = [0n, 1n << 128n]

            await circuit.expectFail(input)
        })
    })
}
