<p align="center">
    <h1 align="center">
        Lean Incremental Merkle Tree Plus (SHA-256)
    </h1>
    <p align="center">Circom circuits to verify membership and non-membership proofs for a LeanIMT+ using full SHA-256.</p>
</p>

<p align="center">
    <a href="https://github.com/zk-kit/zk-kit.circom">
        <img src="https://img.shields.io/badge/project-zk--kit-blue.svg?style=flat-square">
    </a>
    <a href="https://github.com/zk-kit/zk-kit.circom/tree/main/packages/lean-imt-plus-sha256/LICENSE">
        <img alt="NPM license" src="https://img.shields.io/npm/l/%40zk-kit%2Flean-imt-plus-sha256.circom?style=flat-square">
    </a>
    <a href="https://www.npmjs.com/package/@zk-kit/lean-imt-plus-sha256.circom">
        <img alt="NPM version" src="https://img.shields.io/npm/v/@zk-kit/lean-imt-plus-sha256.circom?style=flat-square" />
    </a>
    <a href="https://npmjs.org/package/@zk-kit/lean-imt-plus-sha256.circom">
        <img alt="Downloads" src="https://img.shields.io/npm/dm/@zk-kit/lean-imt-plus-sha256.circom.svg?style=flat-square" />
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

> [!IMPORTANT]
> If you only need **membership** proofs, use [@zk-kit/binary-merkle-root.circom](https://github.com/zk-kit/zk-kit.circom/tree/main/packages/binary-merkle-root) instead: it is the circuit for membership proofs for binary Merkle trees (including the LeanIMT) and is more optimized for that use case. Reach for LeanIMT+ only when you need efficient **non-membership** proofs.

This package provides the `LeanIMTPlusSha256` Circom template, which verifies a **unified LeanIMT+ proof** using SHA-256: it recomputes the Merkle root from the proof and enforces a `proofType`-specific check.

> [!TIP]
> For the Poseidon version, use [@zk-kit/lean-imt-plus.circom](https://github.com/zk-kit/zk-kit.circom/tree/main/packages/lean-imt-plus).

A LeanIMT+ extends the [LeanIMT](https://zkkit.org/leanimt-paper.pdf) with **non-membership proofs** by turning the leaves into an implicit sorted linked list (indexed Merkle tree). A single proof can attest to either:

-   `proofType = 0` (membership): `leafValue == value`.
-   `proofType = 1` (non-membership): `leaf` is the low leaf of `value`, i.e. `leafValue < value` and either `leafNextValue > value` or `leafNextValue == 0` (tail), and the low leaf is not a tombstone.

> [!NOTE]
> For a deeper explanation of how the tree works and its technical details, see the article [LeanIMT+: an efficient Merkle tree for membership and non-membership proofs](https://pse.dev/blog/lean-imt-plus-efficient-merkle-tree-for-membership-and-non-membership-proofs).

### Hashing

Hashing uses the full, untruncated 256-bit SHA-256 digest:

```
H(a, b) = SHA-256(be32(a) || be32(b))
```

where `be32(x)` is the 32-byte big-endian encoding of `x`. This is the same as Solidity's `sha256(abi.encodePacked(bytes32(a), bytes32(b)))`.

-   Leaves: `leafCommitment = SHA-256(be32(value) || be32(nextValue) || be32(TAG_LEAF=1))`, a 96-byte message.
-   Internal nodes: `H(left, right)`, a 64-byte message.

### 256-bit values as `[hi, lo]` limbs

Values can be any 256-bit string (e.g. commitments `C = SHA-256(r)`). Every 256-bit quantity (`value`, `leafValue`, `leafNextValue`, each sibling, and the output root) is passed as two 128-bit limbs `[hi, lo]`, with `x = hi * 2^128 + lo`.

This keeps SHA-256 exact for every input regardless of the native field: even on ~256-bit fields such as secq256r1's scalar field (which equals P-256's base field), a single element cannot hold every digest because `p < 2^256`. The template only relies on 128-bit range checks and comparisons, so it works on any prime field larger than `2^129`, including secq256r1 and bn128.

### Security properties

-   **Domain separation.** Leaves hash 96-byte messages and internal nodes 64-byte messages. SHA-256 encodes the message length in its padding, so a leaf can never be reinterpreted as internal nodes (or vice versa) without a SHA-256 collision.
-   **Depth bound.** `depth` must be in `[0, MAX_DEPTH]`.
-   **Zero-value guard.** `value != 0` is enforced for both proof types, since `0` is reserved for the sentinel and tombstones.
-   **Tombstone replay guard.** In non-membership, the low leaf may have `value == 0` only at index 0 (the sentinel).
-   **Canonical limbs.** Every `[hi, lo]` limb is range-checked to 128 bits, so each 256-bit quantity has a unique encoding, and values are compared limb by limb over the full 256 bits.
-   **Canonical `leafIndex`.** Path bits at positions `>= depth` must be zero, so each physical leaf has a unique encoding.

## 🛠 Install

Install the `@zk-kit/lean-imt-plus-sha256.circom` package with npm:

```bash
npm i @zk-kit/lean-imt-plus-sha256.circom --save
```

or yarn:

```bash
yarn add @zk-kit/lean-imt-plus-sha256.circom
```

## 📜 Usage

Instantiate the template with a static maximum tree depth (`MAX_DEPTH`, which must be below 128). This is a library template and declares no public inputs; wrap it in a protocol-level circuit to pin your own public/private split and to compute any binding (e.g. a nullifier) outside the library.

```circom
pragma circom 2.2.3;

include "lean-imt-plus-sha256.circom";

component main = LeanIMTPlusSha256(10);
```

```bash
circom -l ./node_modules/@zk-kit/lean-imt-plus-sha256.circom/src -l ./node_modules/circomlib/circuits your-circuit.circom
```

To compile over secq256r1 (e.g. for Spartan2 / P-256 based wallets), add `-p secq256r1`.
