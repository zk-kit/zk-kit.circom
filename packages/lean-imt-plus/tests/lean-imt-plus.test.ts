import { assert } from "chai"
import { poseidon2, poseidon3 } from "poseidon-lite"
import { WitnessTester } from "circomkit"
import { circomkit, MAX_DEPTH, toInput, LeanIMTPlus, LeanIMTPlusHashFunctions } from "./common"

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

    it("rejects any proof targeting the zero value", async () => {
        const proof = tree.generateProof(25n)
        await circuit.expectFail({ ...toInput(proof), value: 0n })
    })

    it("rejects an out-of-range value (>= 2^252)", async () => {
        const proof = tree.generateProof(25n)
        const oversize = 1n << 252n
        await circuit.expectFail({ ...toInput(proof), value: oversize })
    })

    it("rejects a non-canonical leafIndex (high bit set past depth)", async () => {
        const proof = tree.generateProof(25n)
        // Set a bit beyond `depth-1`, encoding the same physical position
        // non-canonically. The pastDepth guard must reject this.
        const nonCanonical = proof.leafIndex | (1 << proof.siblings.length)
        await circuit.expectFail({ ...toInput(proof), leafIndex: nonCanonical })
    })

    it("rejects a non-membership proof whose low leaf is a tombstone (zero value at non-zero index)", async () => {
        const proof = tree.generateProof(20n)
        // Forge: keep the genuine leafIndex (non-zero) but set leafValue and
        // leafNextValue to 0, the tombstone shape. The tombstone-replay
        // guard must reject this.
        await circuit.expectFail({ ...toInput(proof), leafValue: 0n, leafNextValue: 0n })
    })
})
