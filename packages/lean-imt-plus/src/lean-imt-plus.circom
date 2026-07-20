pragma circom 2.2.3;

include "poseidon.circom";
include "comparators.circom";
include "mux1.circom";
include "bitify.circom";

// LeanIMTPlus proof verifier (Poseidon variant).
//
// Recomputes the Merkle root from a unified LeanIMT+ proof and enforces the
// proofType-specific check.
//
//   proofType = 0 (membership):     leafValue == value
//   proofType = 1 (non-membership): leafValue < value AND
//                                   (leafNextValue > value OR leafNextValue == 0)
//                                   AND (leafValue != 0 OR leafIndex == 0)
//
// Security properties:
//
//   - Domain separation: leaves are committed with Poseidon(3) over
//     (value, nextValue, TAG_LEAF=1); internal nodes use Poseidon(2). The
//     differing arity prevents an attacker from passing an internal node off
//     as a leaf (second-preimage on the leaf↔internal collision surface).
//
//   - Zero-value guard: `value != 0` is enforced for both proof types so
//     the zero value (reserved for the sentinel and tombstones) cannot be
//     used as a proof target.
//
//   - Tombstone replay guard: in non-membership, the low leaf may have
//     value == 0 ONLY at index 0 (the sentinel). A tombstoned slot
//     (value == 0 at index > 0) is rejected as a low leaf.
//
//   - Bit-width bounds: leafValue, leafNextValue, and value are explicitly
//     constrained to 252 bits each. Without this, `LessThan(252)` could be
//     satisfied via modular wraparound for very large field elements,
//     yielding incorrect ordering decisions.
//
//   - Canonical leafIndex: leafIndex is constrained to fit in `depth` bits,
//     so each physical leaf has a unique encoding. This matters if
//     leafIndex is bound to a downstream identifier (e.g., a nullifier).
//
// The Merkle walk follows the LeanIMT construction used in
// zk-kit's binary-merkle-root.circom: an unpaired right child is promoted
// unchanged, encoded by stopping the walk at `depth` rather than always
// climbing MAX_DEPTH levels.
template LeanIMTPlus(MAX_DEPTH) {
    // Guard against compile-time misconfiguration: `Num2Bits(n)` is only
    // canonical for n strictly below the BN254 scalar bit-length (~254).
    // Bound MAX_DEPTH well under that so `Num2Bits(MAX_DEPTH)` on the
    // leafIndex cannot be supplied a non-canonical decomposition.
    assert(MAX_DEPTH < 252);

    signal input proofType;
    signal input value;
    signal input leafValue;
    signal input leafNextValue;
    signal input leafIndex;
    signal input depth;
    signal input siblings[MAX_DEPTH];

    signal output out;

    // proofType is boolean.
    proofType * (proofType - 1) === 0;

    // Reject the zero value as a proof target. The sentinel has value == 0
    // and tombstones have value == 0; accepting `value == 0` would either
    // let an attacker claim membership of the sentinel or trivialize
    // non-membership of zero.
    component isValueZero = IsZero();
    isValueZero.in <== value;
    isValueZero.out === 0;

    // Bound user-controlled signals to 252 bits so the subsequent
    // LessThan(252) comparators behave correctly. `LessThan(252)` only
    // guarantees a meaningful result when both inputs fit in 252 bits;
    // otherwise modular wraparound on `a + (1<<252) - b` can flip the
    // comparison.
    //
    // NOTE: this is a hard precondition, not just defense-in-depth. These
    // values are ASSUMED to be keys bounded below 2^252. A raw full-field
    // element does NOT satisfy this: a uniform BN254 scalar lands below
    // 2^252 only ~1/3 of the time (r ~= 2^253.6), so ~2/3 of unbounded
    // hash outputs would fail this check. If your protocol's value is a
    // hash (e.g. a nullifier = Poseidon(...)), reduce it into the 252-bit
    // range in-circuit before passing it in, it is not naturally bounded.
    component bitsValue = Num2Bits(252);
    bitsValue.in <== value;
    component bitsLeafValue = Num2Bits(252);
    bitsLeafValue.in <== leafValue;
    component bitsLeafNext = Num2Bits(252);
    bitsLeafNext.in <== leafNextValue;

    // Membership: when proofType == 0, leafValue must equal value.
    (1 - proofType) * (leafValue - value) === 0;

    // Non-membership lower bound: leafValue < value.
    component ltLow = LessThan(252);
    ltLow.in[0] <== leafValue;
    ltLow.in[1] <== value;

    // Non-membership upper bound: leafNextValue > value OR leafNextValue == 0 (tail).
    component ltHigh = LessThan(252);
    ltHigh.in[0] <== value;
    ltHigh.in[1] <== leafNextValue;

    component isTail = IsZero();
    isTail.in <== leafNextValue;

    signal upperOr;
    upperOr <== ltHigh.out + isTail.out - ltHigh.out * isTail.out;

    // Tombstone replay guard: low leaf may have value == 0 only at index 0.
    component isLeafValueZero = IsZero();
    isLeafValueZero.in <== leafValue;
    component isLeafIndexZero = IsZero();
    isLeafIndexZero.in <== leafIndex;
    signal notZeroOrSentinel;
    notZeroOrSentinel <== (1 - isLeafValueZero.out) + isLeafIndexZero.out
                          - (1 - isLeafValueZero.out) * isLeafIndexZero.out;

    signal nonMembOk;
    signal rangeOk;
    rangeOk <== ltLow.out * upperOr;
    nonMembOk <== rangeOk * notZeroOrSentinel;
    proofType * (nonMembOk - 1) === 0;

    // leafHash = Poseidon(leafValue, leafNextValue, TAG_LEAF=1).
    // The 3-input arity is what domain-separates leaves from internal
    // 2-input Poseidon hashes; the constant `1` is the explicit tag.
    component leafHash = Poseidon(3);
    leafHash.inputs[0] <== leafValue;
    leafHash.inputs[1] <== leafNextValue;
    leafHash.inputs[2] <== 1;

    // Path bits: LSB-first packing of leafIndex.
    component bits = Num2Bits(MAX_DEPTH);
    bits.in <== leafIndex;

    // Canonical leafIndex: each bit at position i must be zero whenever
    // i >= depth. Encoded with a running "past-or-at-depth" indicator
    // built from isDepth flags below.
    signal nodes[MAX_DEPTH + 1];
    nodes[0] <== leafHash.out;

    component mux[MAX_DEPTH];
    component hash[MAX_DEPTH];
    component isDepth[MAX_DEPTH];
    signal roots[MAX_DEPTH];
    // pastDepth[i] == 1 iff depth < i. So at i == depth it is still 0,
    // becoming 1 at the next iteration. We want to reject bits[i] when
    // i >= depth, i.e., when pastDepth[i+1] == 1.
    signal pastDepth[MAX_DEPTH + 1];
    pastDepth[0] <== 0;
    var rootSum = 0;

    for (var i = 0; i < MAX_DEPTH; i++) {
        isDepth[i] = IsEqual();
        isDepth[i].in[0] <== depth;
        isDepth[i].in[1] <== i;
        roots[i] <== isDepth[i].out * nodes[i];
        rootSum += roots[i];

        pastDepth[i + 1] <== pastDepth[i] + isDepth[i].out;

        // Enforce canonical encoding: if i is at or beyond depth, the path
        // bit at position i must be 0.
        bits.out[i] * pastDepth[i + 1] === 0;

        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== nodes[i];
        mux[i].c[0][1] <== siblings[i];
        mux[i].c[1][0] <== siblings[i];
        mux[i].c[1][1] <== nodes[i];
        mux[i].s <== bits.out[i];

        hash[i] = Poseidon(2);
        hash[i].inputs[0] <== mux[i].out[0];
        hash[i].inputs[1] <== mux[i].out[1];
        nodes[i + 1] <== hash[i].out;
    }

    component isMaxDepth = IsEqual();
    isMaxDepth.in[0] <== depth;
    isMaxDepth.in[1] <== MAX_DEPTH;
    out <== rootSum + isMaxDepth.out * nodes[MAX_DEPTH];
}
