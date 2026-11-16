import { Circomkit } from "circomkit"
import { readFileSync } from "fs"
import path from "path"
import { LeanIMTPlus, LeanIMTPlusHashFunctions, LeanIMTPlusProof } from "@zk-kit/lean-imt-plus"

const configFilePath = path.join(__dirname, "../circomkit.json")
const config = JSON.parse(readFileSync(configFilePath, "utf-8"))

export const circomkit = new Circomkit({
    ...config,
    verbose: false
})

// Must match `circuits.json`.
export const MAX_DEPTH = 10

// Proof to circuit inputs, padding siblings to MAX_DEPTH.
export function toInput(p: LeanIMTPlusProof<bigint>) {
    const depth = p.siblings.length
    const siblings = [...p.siblings]
    while (siblings.length < MAX_DEPTH) siblings.push(0n)

    return {
        proofType: p.proofType,
        value: p.value,
        leafValue: p.leaf.value,
        leafNextValue: p.leaf.nextValue,
        leafIndex: p.leafIndex,
        depth,
        siblings
    }
}

// Real proof for any physical slot (e.g. a tombstone), rebuilt from the
// exported nodes with the LeanIMT rules: levels without a sibling are skipped.
export function proofAt(
    tree: LeanIMTPlus<bigint>,
    index: number,
    proofType: 0 | 1,
    value: bigint
): LeanIMTPlusProof<bigint> {
    const data = JSON.parse(tree.export())
    const nodes: bigint[][] = data.nodes.map((level: string[]) => level.map(BigInt))
    const { value: leafValue, nextValue } = data.leaves[index]
    const siblings: bigint[] = []
    let leafIndex = 0
    let i = index

    for (let level = 0; level < nodes.length - 1; level++) {
        const isRight = (i & 1) === 1
        const sibling = isRight ? i - 1 : i + 1

        if (sibling < nodes[level].length) {
            if (isRight) leafIndex |= 1 << siblings.length
            siblings.push(nodes[level][sibling])
        }

        i >>= 1
    }

    return {
        proofType,
        root: nodes[nodes.length - 1][0],
        value,
        leaf: { value: BigInt(leafValue), nextValue: BigInt(nextValue) },
        leafIndex,
        siblings
    }
}

// Off-circuit root recomputation, mirroring the circuit.
export function computeRoot(p: LeanIMTPlusProof<bigint>, hashes: LeanIMTPlusHashFunctions<bigint>): bigint {
    let node = hashes.leaf(p.leaf.value, p.leaf.nextValue, 1n)

    p.siblings.forEach((sibling, i) => {
        node = (p.leafIndex >> i) & 1 ? hashes.internal(sibling, node) : hashes.internal(node, sibling)
    })

    return node
}

export * from "@zk-kit/lean-imt-plus"
