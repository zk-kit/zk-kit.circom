<p align="center">
    <h1 align="center">
        Binary Merkle Root SHA-256
    </h1>
    <p align="center">A circuit to calculate the root of a SHA-256 binary Merkle tree using a provided proof-of-membership.</p>
</p>

<p align="center">
    <a href="https://github.com/zk-kit/zk-kit.circom">
        <img src="https://img.shields.io/badge/project-zk--kit-blue.svg?style=flat-square">
    </a>
    <a href="https://github.com/zk-kit/zk-kit.circom/tree/main/packages/binary-merkle-root-sha256/LICENSE">
        <img alt="NPM license" src="https://img.shields.io/npm/l/%40zk-kit%2Fbinary-merkle-root-sha256.circom?style=flat-square">
    </a>
    <a href="https://www.npmjs.com/package/@zk-kit/binary-merkle-root-sha256.circom">
        <img alt="NPM version" src="https://img.shields.io/npm/v/@zk-kit/binary-merkle-root-sha256.circom?style=flat-square" />
    </a>
    <a href="https://npmjs.org/package/@zk-kit/binary-merkle-root-sha256.circom">
        <img alt="Downloads" src="https://img.shields.io/npm/dm/@zk-kit/binary-merkle-root-sha256.circom.svg?style=flat-square" />
    </a>
</p>

<div align="center">
    <h4>
        <span>&nbsp;&nbsp;|&nbsp;&nbsp;</span>
        <a href="https://github.com/zk-kit/zk-kit.circom/issues/new/choose">
            🔎 Issues
        </a>
        <span>&nbsp;&nbsp;|&nbsp;&nbsp;</span>
    </h4>
</div>

This package provides the `BinaryMerkleRootSha256` Circom template, the SHA-256 version of [@zk-kit/binary-merkle-root.circom](https://github.com/zk-kit/zk-kit.circom/tree/main/packages/binary-merkle-root). It recomputes the root of a binary Merkle tree (including the [LeanIMT](https://zkkit.org/leanimt-paper.pdf)) from a leaf and its proof of membership.

> [!TIP]
> For the Poseidon version, use [@zk-kit/binary-merkle-root.circom](https://github.com/zk-kit/zk-kit.circom/tree/main/packages/binary-merkle-root).

### Hashing

Internal nodes use the full, untruncated 256-bit SHA-256 digest:

```
H(left, right) = SHA-256(be32(left) || be32(right))
```

where `be32(x)` is the 32-byte big-endian encoding of `x`. This is the same as Solidity's `sha256(abi.encodePacked(bytes32(left), bytes32(right)))`. Leaves are used as they are, as in the LeanIMT, so the root of a single-leaf tree is the leaf itself.

The off-chain tree must use the same hash function, for example:

```ts
import { LeanIMT } from "@zk-kit/lean-imt"
import { createHash } from "crypto"

const be32 = (x: bigint) => Buffer.from(x.toString(16).padStart(64, "0"), "hex")

const hash = (a: bigint, b: bigint) =>
    BigInt(
        `0x${createHash("sha256")
            .update(Buffer.concat([be32(a), be32(b)]))
            .digest("hex")}`
    )

const tree = new LeanIMT(hash)
```

### 256-bit values as `[hi, lo]` limbs

Leaves can be any 256-bit string (e.g. commitments `C = SHA-256(r)`). Every 256-bit quantity (the `leaf`, each sibling, and the output root) is passed as two 128-bit limbs `[hi, lo]`, with `x = hi * 2^128 + lo`.

This keeps SHA-256 exact for every input regardless of the native field: even on ~256-bit fields such as secq256r1's scalar field (which equals P-256's base field), a single element cannot hold every digest because `p < 2^256`. The template only relies on 128-bit range checks, so it works on any prime field larger than `2^129`, including secq256r1 and bn128.

### Inputs and output

-   `leaf[2]`: the leaf, as `[hi, lo]` limbs.
-   `depth`: the actual depth of the tree. It must be in `[0, MAX_DEPTH]`.
-   `index`: the leaf index, whose binary representation defines the path indices. It must fit in `MAX_DEPTH` bits.
-   `siblings[MAX_DEPTH][2]`: the sibling nodes as `[hi, lo]` limbs, padded with `[0, 0]` up to `MAX_DEPTH`.
-   `out[2]`: the computed Merkle root, as `[hi, lo]` limbs.

### Security properties

-   **Depth bound.** `depth` must be in `[0, MAX_DEPTH]`. Unlike `BinaryMerkleRoot`, the circuit enforces it, so it never outputs a `[0, 0]` root.
-   **Canonical limbs.** Every `[hi, lo]` limb is range-checked to 128 bits, so each 256-bit quantity has a unique encoding.

> [!NOTE]
> As with `BinaryMerkleRoot`, the bits of `index` at positions `>= depth` are not constrained, so the same leaf can be proven with several `index` values. Do not use `index` as a unique identifier of a leaf (e.g. in a nullifier) without constraining it.

## 🛠 Install

Install the `@zk-kit/binary-merkle-root-sha256.circom` package with npm:

```bash
npm i @zk-kit/binary-merkle-root-sha256.circom --save
```

or yarn:

```bash
yarn add @zk-kit/binary-merkle-root-sha256.circom
```

## 📜 Usage

Instantiate the template with a static maximum tree depth (`MAX_DEPTH`, which must be below 128):

```circom
pragma circom 2.2.3;

include "binary-merkle-root-sha256.circom";

component main = BinaryMerkleRootSha256(10);
```

```bash
circom -l ./node_modules/@zk-kit/binary-merkle-root-sha256.circom/src -l ./node_modules/circomlib/circuits your-circuit.circom
```

To compile over secq256r1 (e.g. for Spartan2 / P-256 based wallets), add `-p secq256r1`.
