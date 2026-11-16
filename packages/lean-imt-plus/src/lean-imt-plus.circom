pragma circom 2.2.3;

include "poseidon.circom";
include "comparators.circom";
include "mux1.circom";
include "bitify.circom";

// LeanIMT+ proof verifier (Poseidon). Recomputes the root and checks:
//   proofType = 0 (membership):     leafValue == value
//   proofType = 1 (non-membership): leafValue < value
//                                   AND (leafNextValue > value OR leafNextValue == 0)
//                                   AND (leafValue != 0 OR leafIndex == 0)
// Leaves are Poseidon(value, nextValue, 1) and internal nodes Poseidon(left, right);
// the different arity domain-separates them. Unpaired nodes are promoted as in LeanIMT.
template LeanIMTPlus(MAX_DEPTH) {
    // Keeps Num2Bits(MAX_DEPTH) on leafIndex canonical on BN254.
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

    // 0 is reserved for the sentinel and tombstones.
    component isValueZero = IsZero();
    isValueZero.in <== value;
    isValueZero.out === 0;

    // LessThan(252) is only sound for inputs below 2^252. Values must already
    // be in that range; reduce hash outputs in-circuit before passing them in.
    component bitsValue = Num2Bits(252);
    bitsValue.in <== value;
    component bitsLeafValue = Num2Bits(252);
    bitsLeafValue.in <== leafValue;
    component bitsLeafNext = Num2Bits(252);
    bitsLeafNext.in <== leafNextValue;

    (1 - proofType) * (leafValue - value) === 0;

    component ltLow = LessThan(252);
    ltLow.in[0] <== leafValue;
    ltLow.in[1] <== value;

    // Upper bound holds if leafNextValue > value or the low leaf is the tail.
    component ltHigh = LessThan(252);
    ltHigh.in[0] <== value;
    ltHigh.in[1] <== leafNextValue;

    component isTail = IsZero();
    isTail.in <== leafNextValue;

    signal upperOr;
    upperOr <== ltHigh.out + isTail.out - ltHigh.out * isTail.out;

    // Tombstone guard: a low leaf with value 0 must be the sentinel (index 0).
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

    component leafHash = Poseidon(3);
    leafHash.inputs[0] <== leafValue;
    leafHash.inputs[1] <== leafNextValue;
    leafHash.inputs[2] <== 1;

    component bits = Num2Bits(MAX_DEPTH);
    bits.in <== leafIndex;

    signal nodes[MAX_DEPTH + 1];
    nodes[0] <== leafHash.out;

    component mux[MAX_DEPTH];
    component hash[MAX_DEPTH];
    component isDepth[MAX_DEPTH];
    signal roots[MAX_DEPTH];
    // pastDepth[i + 1] == 1 iff i >= depth.
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

        // Canonical leafIndex: path bits at or past depth must be 0.
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
    // depth must be in [0, MAX_DEPTH]; otherwise the root would be 0.
    pastDepth[MAX_DEPTH] + isMaxDepth.out === 1;
    out <== rootSum + isMaxDepth.out * nodes[MAX_DEPTH];
}
