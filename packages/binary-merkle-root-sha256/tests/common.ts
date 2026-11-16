import { LeanIMT } from "@zk-kit/lean-imt"
import { Circomkit } from "circomkit"
import { createHash } from "crypto"
import { readFileSync } from "fs"
import path from "path"

const configFilePath = path.join(__dirname, "../circomkit.json")
const config = JSON.parse(readFileSync(configFilePath, "utf-8"))

export const circomkit = new Circomkit({
    ...config,
    verbose: false
})

const MASK_128 = (1n << 128n) - 1n

function toBE32(x: bigint): Uint8Array {
    const buf = new Uint8Array(32)
    let v = x
    for (let i = 31; i >= 0; i -= 1) {
        buf[i] = Number(v & 0xffn)
        v >>= 8n
    }
    return buf
}

function digestToBigInt(digest: Buffer): bigint {
    return BigInt(`0x${digest.toString("hex")}`)
}

// H(a, b) = SHA-256(be32(a) || be32(b)).
export function sha256Hash2(a: bigint, b: bigint): bigint {
    const buf = new Uint8Array(64)
    buf.set(toBE32(a), 0)
    buf.set(toBE32(b), 32)
    return digestToBigInt(createHash("sha256").update(buf).digest())
}

// 256-bit leaf: SHA-256(r).
export function commitment(r: string): bigint {
    return digestToBigInt(createHash("sha256").update(r).digest())
}

// 256-bit value to [hi, lo] 128-bit limbs.
export function toLimbs(x: bigint): [bigint, bigint] {
    return [x >> 128n, x & MASK_128]
}

export type BinaryMerkleTreeProof = {
    leaf: bigint
    depth: number
    index: number
    siblings: bigint[]
    root: bigint
}

// LeanIMT of SHA-256("0"), ..., SHA-256(nodes - 1) and the proof of `leafIndex`, siblings padded to `maxDepth`.
export const generateBinaryMerkleRoot = (maxDepth = 5, nodes = 32, leafIndex = 0): BinaryMerkleTreeProof => {
    const tree = new LeanIMT(sha256Hash2)

    for (let i = 0; i < nodes; i += 1) {
        tree.insert(commitment(i.toString()))
    }

    const leaf = tree.leaves[leafIndex]

    const { siblings, index } = tree.generateProof(leafIndex)

    const depth = siblings.length

    // Unused siblings are ignored by the circuit.
    for (let i = 0; i < maxDepth; i += 1) {
        if (siblings[i] === undefined) {
            siblings[i] = BigInt(0)
        }
    }

    return {
        leaf,
        depth,
        index,
        siblings,
        root: tree.root
    }
}

// Proof to circuit inputs.
export function toInput({ leaf, depth, index, siblings }: BinaryMerkleTreeProof) {
    return {
        leaf: toLimbs(leaf),
        depth,
        index,
        siblings: siblings.map(toLimbs)
    }
}
