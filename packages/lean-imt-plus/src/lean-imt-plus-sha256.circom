pragma circom 2.2.3;

include "sha256/sha256_2.circom";
include "comparators.circom";
include "mux1.circom";
include "bitify.circom";

// SHA-256 variant of the LeanIMT+ proof verifier.
//
// `Sha256_2` packs each input as a 216-bit big-endian integer and emits the
// lower 216 bits of the 256-bit digest. Inputs (user values and sibling
// hashes) must fit in 216 bits. The TS-side hash helper truncates to 216
// bits, so on-chain and off-chain commitments line up only when callers
// keep their values inside this range.
//
// Leaves are committed as
//   leafCommitment = Sha256_2(Sha256_2(value, nextValue), TAG_LEAF=1)
// while internal nodes are committed as
//   internal = Sha256_2(left, right).
//
// The extra wrapping pass with the constant tag `1` provides domain
// separation between leaves and internal nodes: an internal-node hash
// `Sha256_2(L, R)` could only collide with a leaf commitment if R = 1, and
// R is always a pseudorandom 216-bit digest produced by Sha256_2, the
// probability of any tree node having R = 1 is 2^-216.
//
// Security guards mirror the Poseidon variant:
//   - `value != 0`
//   - non-membership lower/upper bounds with 216-bit input bounds
//   - tombstone replay guard: `leafValue != 0` OR `leafIndex == 0`
//   - canonical leafIndex: bits at positions >= depth must be 0
template LeanIMTPlusSha256(MAX_DEPTH) {
    // See lean-imt-plus.circom for the rationale.
    assert(MAX_DEPTH < 252);

    signal input proofType;
    signal input value;
    signal input leafValue;
    signal input leafNextValue;
    signal input leafIndex;
    signal input depth;
    signal input siblings[MAX_DEPTH];

    signal output out;

    proofType * (proofType - 1) === 0;

    // Reject the zero value as a proof target.
    component isValueZero = IsZero();
    isValueZero.in <== value;
    isValueZero.out === 0;

    // Bound user-controlled signals. SHA-256 leaf inputs are encoded in
    // 216 bits inside `Sha256_2`, so values must fit in that range or the
    // on-chain commitment will not match the TS-side hash.
    //
    // NOTE: this is a hard precondition. These values are ASSUMED to be
    // keys bounded below 2^216. A raw full-field element (e.g. an
    // untruncated hash output) does NOT satisfy this and would fail the
    // check. If your protocol's value is a hash, reduce it into the
    // 216-bit range in-circuit before passing it in.
    component bitsValue = Num2Bits(216);
    bitsValue.in <== value;
    component bitsLeafValue = Num2Bits(216);
    bitsLeafValue.in <== leafValue;
    component bitsLeafNext = Num2Bits(216);
    bitsLeafNext.in <== leafNextValue;

    (1 - proofType) * (leafValue - value) === 0;

    component ltLow = LessThan(252);
    ltLow.in[0] <== leafValue;
    ltLow.in[1] <== value;

    component ltHigh = LessThan(252);
    ltHigh.in[0] <== value;
    ltHigh.in[1] <== leafNextValue;

    component isTail = IsZero();
    isTail.in <== leafNextValue;

    signal upperOr;
    upperOr <== ltHigh.out + isTail.out - ltHigh.out * isTail.out;

    // Tombstone replay guard.
    component isLeafValueZero = IsZero();
    isLeafValueZero.in <== leafValue;
    component isLeafIndexZero = IsZero();
    isLeafIndexZero.in <== leafIndex;
    signal notZeroOrSentinel;
    notZeroOrSentinel <== (1 - isLeafValueZero.out) + isLeafIndexZero.out
                          - (1 - isLeafValueZero.out) * isLeafIndexZero.out;

    signal rangeOk;
    signal nonMembOk;
    rangeOk <== ltLow.out * upperOr;
    nonMembOk <== rangeOk * notZeroOrSentinel;
    proofType * (nonMembOk - 1) === 0;

    // Leaf commitment: outer Sha256_2 of (inner commitment, TAG_LEAF=1).
    component leafInner = Sha256_2();
    leafInner.a <== leafValue;
    leafInner.b <== leafNextValue;

    component leafHash = Sha256_2();
    leafHash.a <== leafInner.out;
    leafHash.b <== 1;

    component bits = Num2Bits(MAX_DEPTH);
    bits.in <== leafIndex;

    signal nodes[MAX_DEPTH + 1];
    nodes[0] <== leafHash.out;

    component mux[MAX_DEPTH];
    component hash[MAX_DEPTH];
    component isDepth[MAX_DEPTH];
    signal roots[MAX_DEPTH];
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
        // Canonical leafIndex: bits past depth must be 0.
        bits.out[i] * pastDepth[i + 1] === 0;

        mux[i] = MultiMux1(2);
        mux[i].c[0][0] <== nodes[i];
        mux[i].c[0][1] <== siblings[i];
        mux[i].c[1][0] <== siblings[i];
        mux[i].c[1][1] <== nodes[i];
        mux[i].s <== bits.out[i];

        hash[i] = Sha256_2();
        hash[i].a <== mux[i].out[0];
        hash[i].b <== mux[i].out[1];
        nodes[i + 1] <== hash[i].out;
    }

    component isMaxDepth = IsEqual();
    isMaxDepth.in[0] <== depth;
    isMaxDepth.in[1] <== MAX_DEPTH;
    out <== rootSum + isMaxDepth.out * nodes[MAX_DEPTH];
}
