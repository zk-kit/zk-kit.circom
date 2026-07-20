import { Circomkit } from "circomkit"
import { readFileSync } from "fs"
import path from "path"
import { LeanIMTPlusProof } from "@zk-kit/lean-imt-plus"

const configFilePath = path.join(__dirname, "../circomkit.json")
const config = JSON.parse(readFileSync(configFilePath, "utf-8"))

export const circomkit = new Circomkit({
    ...config,
    verbose: false
})

// Static maximum tree depth the circuits are instantiated with (see
// `circuits.json`). Proofs are padded to this many siblings.
export const MAX_DEPTH = 10

/**
 * Flattens a `LeanIMTPlusProof` into the input signals expected by the
 * `lean-imt-plus` / `lean-imt-plus-sha256` circuits, padding `siblings`
 * with zeros up to `MAX_DEPTH`.
 */
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

export * from "@zk-kit/lean-imt-plus"
