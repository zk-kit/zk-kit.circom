<p align="center">
    <h1 align="center">
        Lean Incremental Merkle Tree Plus
    </h1>
    <p align="center">Circom circuits to verify membership and non-membership proofs for a LeanIMT+.</p>
</p>

<p align="center">
    <a href="https://github.com/privacy-scaling-explorations/zk-kit.circom">
        <img src="https://img.shields.io/badge/project-zk--kit-blue.svg?style=flat-square">
    </a>
    <a href="https://github.com/privacy-scaling-explorations/zk-kit.circom/tree/main/packages/lean-imt-plus/LICENSE">
        <img alt="NPM license" src="https://img.shields.io/npm/l/%40zk-kit%2Flean-imt-plus.circom?style=flat-square">
    </a>
    <a href="https://www.npmjs.com/package/@zk-kit/lean-imt-plus.circom">
        <img alt="NPM version" src="https://img.shields.io/npm/v/@zk-kit/lean-imt-plus.circom?style=flat-square" />
    </a>
    <a href="https://npmjs.org/package/@zk-kit/lean-imt-plus.circom">
        <img alt="Downloads" src="https://img.shields.io/npm/dm/@zk-kit/lean-imt-plus.circom.svg?style=flat-square" />
    </a>
</p>

<div align="center">
    <h4>
        <span>&nbsp;&nbsp;|&nbsp;&nbsp;</span>
        <a href="https://github.com/privacy-scaling-explorations/zk-kit.circom/issues/new/choose">
            🔎 Issues
        </a>
        <span>&nbsp;&nbsp;|&nbsp;&nbsp;</span>
    </h4>
</div>

> [!IMPORTANT]
> If you only need **membership** proofs, use [@zk-kit/binary-merkle-root.circom](https://github.com/zk-kit/zk-kit.circom/tree/main/packages/binary-merkle-root) instead: it is the circuit for membership proofs for binary Merkle trees (including the LeanIMT) and is more optimized for that use case. Reach for LeanIMT+ only when you need efficient **non-membership** proofs.

This package provides two Circom templates that verify a **unified LeanIMT+ proof**, recomputing the Merkle root from the proof and enforcing a `proofType`-specific check:

-   `LeanIMTPlus`: Poseidon variant.
-   `LeanIMTPlusSha256`: SHA-256 variant (uses `Sha256_2`).

A LeanIMT+ extends the [LeanIMT](https://zkkit.org/leanimt-paper.pdf) with **non-membership proofs** by turning the leaves into an implicit sorted linked list (indexed Merkle tree). A single proof can attest to either:

-   `proofType = 0` (membership): `leafValue == value`.
-   `proofType = 1` (non-membership): `leaf` is the low leaf of `value`, i.e. `leafValue < value` and either `leafNextValue > value` or `leafNextValue == 0` (tail), and the low leaf is not a tombstone.

> [!NOTE]
> For a deeper explanation of how the tree works and its technical details, see the article [LeanIMT+: an efficient Merkle tree for membership and non-membership proofs](https://pse.dev/blog/lean-imt-plus-efficient-merkle-tree-for-membership-and-non-membership-proofs).

### Security properties

-   **Domain separation.** Leaves are committed with an arity-3 hash over `(value, nextValue, TAG_LEAF=1)`; internal nodes use an arity-2 hash. The differing arity prevents passing an internal node off as a leaf.
-   **Zero-value guard.** `value != 0` is enforced for both proof types, since `0` is reserved for the sentinel and tombstones.
-   **Tombstone replay guard.** In non-membership, the low leaf may have `value == 0` only at index 0 (the sentinel).
-   **Bit-width bounds.** `value`, `leafValue`, and `leafNextValue` are bounded (252 bits for Poseidon, 216 bits for SHA-256) so the `LessThan` comparators cannot be defeated by modular wraparound.
-   **Canonical `leafIndex`.** Path bits at positions `>= depth` must be zero, so each physical leaf has a unique encoding.

> [!IMPORTANT]
> The bit-width bounds are a hard precondition: `value`, `leafValue` and `leafNextValue` are ASSUMED to be keys bounded below `2^252` (Poseidon) or `2^216` (SHA-256). A raw full-field element (e.g. an untruncated hash output) does NOT satisfy this. If your protocol's value is a hash, reduce it into range in-circuit before passing it in.

## 🛠 Install

Install the `@zk-kit/lean-imt-plus.circom` package with npm:

```bash
npm i @zk-kit/lean-imt-plus.circom --save
```

or yarn:

```bash
yarn add @zk-kit/lean-imt-plus.circom
```

## 📜 Usage

Instantiate the template you need with a static maximum tree depth (`MAX_DEPTH`). These are library templates and declare no public inputs; wrap them in a protocol-level circuit to pin your own public/private split and to compute any binding (e.g. a nullifier) outside the library.

```circom
pragma circom 2.2.3;

include "lean-imt-plus.circom";

component main = LeanIMTPlus(10);
```

or the SHA-256 variant:

```circom
pragma circom 2.2.3;

include "lean-imt-plus-sha256.circom";

component main = LeanIMTPlusSha256(10);
```

```bash
circom -l ./node_modules/@zk-kit/lean-imt-plus.circom/src -l ./node_modules/circomlib/circuits your-circuit.circom
```
