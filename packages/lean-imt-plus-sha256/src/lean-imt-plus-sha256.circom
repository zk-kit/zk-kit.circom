pragma circom 2.2.3;

include "sha256/sha256.circom";
include "comparators.circom";
include "bitify.circom";

// LeanIMT+ proof verifier (SHA-256). Same checks as the Poseidon variant.
//
// H(a, b) = SHA-256(be32(a) || be32(b)), the full 256-bit digest (Solidity's
// sha256(abi.encodePacked(bytes32(a), bytes32(b)))).
// Leaves are SHA-256(be32(value) || be32(nextValue) || be32(1)) and internal
// nodes H(left, right).
//
// 256-bit values, siblings and the root are [hi, lo] 128-bit limbs, since a
// single field element cannot hold every digest (even on secq256r1, p < 2^256).
// Works on any prime field larger than 2^129.

// [hi, lo] limbs to big-endian bits, range-checking each limb to 128 bits.
template LeanIMTPlusSha256LimbsToBits() {
    signal input in[2];
    signal output out[256];

    component hi = Num2Bits(128);
    hi.in <== in[0];
    component lo = Num2Bits(128);
    lo.in <== in[1];

    for (var i = 0; i < 128; i++) {
        out[i] <== hi.out[127 - i];
        out[128 + i] <== lo.out[127 - i];
    }
}

// Big-endian bits to [hi, lo] limbs (linear, no extra constraints).
template LeanIMTPlusSha256BitsToLimbs() {
    signal input in[256];
    signal output out[2];

    var hi = 0;
    var lo = 0;
    for (var i = 0; i < 128; i++) {
        hi += in[i] * (1 << (127 - i));
        lo += in[128 + i] * (1 << (127 - i));
    }
    out[0] <== hi;
    out[1] <== lo;
}

// 256-bit a < b. Limbs must already be range-checked to 128 bits.
template LeanIMTPlusSha256LessThan() {
    signal input a[2];
    signal input b[2];
    signal output out;

    component ltHi = LessThan(128);
    ltHi.in[0] <== a[0];
    ltHi.in[1] <== b[0];

    component eqHi = IsEqual();
    eqHi.in[0] <== a[0];
    eqHi.in[1] <== b[0];

    component ltLo = LessThan(128);
    ltLo.in[0] <== a[1];
    ltLo.in[1] <== b[1];

    // ltHi and eqHi are mutually exclusive, so the sum is an OR.
    signal hiEqLoLt;
    hiEqLoLt <== eqHi.out * ltLo.out;
    out <== ltHi.out + hiEqLoLt;
}

// 256-bit x == 0. Limbs must already be range-checked, so hi + lo cannot wrap.
template LeanIMTPlusSha256IsZero() {
    signal input in[2];
    signal output out;

    out <== IsZero()(in[0] + in[1]);
}

template LeanIMTPlusSha256(MAX_DEPTH) {
    // Keeps Num2Bits(MAX_DEPTH) on leafIndex canonical on any supported field.
    assert(MAX_DEPTH < 128);

    signal input proofType;
    signal input value[2];
    signal input leafValue[2];
    signal input leafNextValue[2];
    signal input leafIndex;
    signal input depth;
    signal input siblings[MAX_DEPTH][2];

    signal output out[2];

    proofType * (proofType - 1) === 0;

    // Range checks; the same bits feed the hash.
    component valueBits = LeanIMTPlusSha256LimbsToBits();
    valueBits.in <== value;
    component leafValueBits = LeanIMTPlusSha256LimbsToBits();
    leafValueBits.in <== leafValue;
    component leafNextBits = LeanIMTPlusSha256LimbsToBits();
    leafNextBits.in <== leafNextValue;

    // 0 is reserved for the sentinel and tombstones.
    component isValueZero = LeanIMTPlusSha256IsZero();
    isValueZero.in <== value;
    isValueZero.out === 0;

    for (var k = 0; k < 2; k++) {
        (1 - proofType) * (leafValue[k] - value[k]) === 0;
    }

    component ltLow = LeanIMTPlusSha256LessThan();
    ltLow.a <== leafValue;
    ltLow.b <== value;

    component ltHigh = LeanIMTPlusSha256LessThan();
    ltHigh.a <== value;
    ltHigh.b <== leafNextValue;

    component isTail = LeanIMTPlusSha256IsZero();
    isTail.in <== leafNextValue;

    signal upperOr;
    upperOr <== ltHigh.out + isTail.out - ltHigh.out * isTail.out;

    // Tombstone guard: a low leaf with value 0 must be the sentinel (index 0).
    component isLeafValueZero = LeanIMTPlusSha256IsZero();
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

    // 96-byte leaf message vs 64-byte internal message: SHA-256 encodes the
    // length, so a leaf can never be reinterpreted as internal levels.
    component leafHash = Sha256(768);
    for (var j = 0; j < 256; j++) {
        leafHash.in[j] <== leafValueBits.out[j];
        leafHash.in[256 + j] <== leafNextBits.out[j];
        // be32(1)
        leafHash.in[512 + j] <== j == 255 ? 1 : 0;
    }

    component bits = Num2Bits(MAX_DEPTH);
    bits.in <== leafIndex;

    signal nodes[MAX_DEPTH + 1][256];
    nodes[0] <== leafHash.out;

    component nodeLimbs[MAX_DEPTH + 1];
    component siblingBits[MAX_DEPTH];
    component hash[MAX_DEPTH];
    component isDepth[MAX_DEPTH];
    signal left[MAX_DEPTH][256];
    signal roots[MAX_DEPTH][2];
    signal pastDepth[MAX_DEPTH + 1];
    pastDepth[0] <== 0;
    var rootSum[2] = [0, 0];

    for (var i = 0; i < MAX_DEPTH; i++) {
        nodeLimbs[i] = LeanIMTPlusSha256BitsToLimbs();
        nodeLimbs[i].in <== nodes[i];

        isDepth[i] = IsEqual();
        isDepth[i].in[0] <== depth;
        isDepth[i].in[1] <== i;
        for (var k = 0; k < 2; k++) {
            roots[i][k] <== isDepth[i].out * nodeLimbs[i].out[k];
            rootSum[k] += roots[i][k];
        }

        pastDepth[i + 1] <== pastDepth[i] + isDepth[i].out;
        // Canonical leafIndex: path bits at or past depth must be 0.
        bits.out[i] * pastDepth[i + 1] === 0;

        siblingBits[i] = LeanIMTPlusSha256LimbsToBits();
        siblingBits[i].in <== siblings[i];

        hash[i] = Sha256(512);
        for (var j = 0; j < 256; j++) {
            left[i][j] <== bits.out[i] * (siblingBits[i].out[j] - nodes[i][j]) + nodes[i][j];
            hash[i].in[j] <== left[i][j];
            hash[i].in[256 + j] <== nodes[i][j] + siblingBits[i].out[j] - left[i][j];
        }
        nodes[i + 1] <== hash[i].out;
    }

    nodeLimbs[MAX_DEPTH] = LeanIMTPlusSha256BitsToLimbs();
    nodeLimbs[MAX_DEPTH].in <== nodes[MAX_DEPTH];

    component isMaxDepth = IsEqual();
    isMaxDepth.in[0] <== depth;
    isMaxDepth.in[1] <== MAX_DEPTH;
    // depth must be in [0, MAX_DEPTH]; otherwise the root would be [0, 0].
    pastDepth[MAX_DEPTH] + isMaxDepth.out === 1;
    for (var k = 0; k < 2; k++) {
        out[k] <== rootSum[k] + isMaxDepth.out * nodeLimbs[MAX_DEPTH].out[k];
    }
}
