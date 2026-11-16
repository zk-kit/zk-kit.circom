pragma circom 2.2.3;

include "sha256/sha256.circom";
include "comparators.circom";
include "bitify.circom";

// SHA-256 version of BinaryMerkleRoot: computes the root of a binary Merkle
// tree (e.g. a LeanIMT) from a leaf and its proof.
//
// H(a, b) = SHA-256(be32(a) || be32(b)), the full 256-bit digest.
// 256-bit values are [hi, lo] 128-bit limbs (a field element can't hold every
// digest, even on secq256r1). Works on any prime field larger than 2^129.
// `depth` is dynamic and must be <= MAX_DEPTH (enforced).

// [hi, lo] limbs to big-endian bits, with 128-bit range checks.
template BinaryMerkleRootSha256LimbsToBits() {
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

// Big-endian bits to [hi, lo] limbs (linear).
template BinaryMerkleRootSha256BitsToLimbs() {
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

template BinaryMerkleRootSha256(MAX_DEPTH) {
    // Keeps Num2Bits(MAX_DEPTH) canonical on any supported field.
    assert(MAX_DEPTH < 128);

    signal input leaf[2];
    signal input depth;
    signal input index;
    signal input siblings[MAX_DEPTH][2];

    signal output out[2];

    component leafBits = BinaryMerkleRootSha256LimbsToBits();
    leafBits.in <== leaf;

    component indices = Num2Bits(MAX_DEPTH);
    indices.in <== index;

    signal nodes[MAX_DEPTH + 1][256];
    nodes[0] <== leafBits.out;

    component nodeLimbs[MAX_DEPTH + 1];
    component siblingBits[MAX_DEPTH];
    component hash[MAX_DEPTH];
    component isDepth[MAX_DEPTH];
    signal left[MAX_DEPTH][256];
    signal roots[MAX_DEPTH][2];
    var root[2] = [0, 0];
    var depthMatches = 0;

    for (var i = 0; i < MAX_DEPTH; i++) {
        nodeLimbs[i] = BinaryMerkleRootSha256BitsToLimbs();
        nodeLimbs[i].in <== nodes[i];

        isDepth[i] = IsEqual();
        isDepth[i].in[0] <== depth;
        isDepth[i].in[1] <== i;
        depthMatches += isDepth[i].out;
        for (var k = 0; k < 2; k++) {
            roots[i][k] <== isDepth[i].out * nodeLimbs[i].out[k];
            root[k] += roots[i][k];
        }

        siblingBits[i] = BinaryMerkleRootSha256LimbsToBits();
        siblingBits[i].in <== siblings[i];

        // indices[i] ? H(sibling, node) : H(node, sibling).
        hash[i] = Sha256(512);
        for (var j = 0; j < 256; j++) {
            left[i][j] <== indices.out[i] * (siblingBits[i].out[j] - nodes[i][j]) + nodes[i][j];
            hash[i].in[j] <== left[i][j];
            hash[i].in[256 + j] <== nodes[i][j] + siblingBits[i].out[j] - left[i][j];
        }
        nodes[i + 1] <== hash[i].out;
    }

    nodeLimbs[MAX_DEPTH] = BinaryMerkleRootSha256BitsToLimbs();
    nodeLimbs[MAX_DEPTH].in <== nodes[MAX_DEPTH];

    component isMaxDepth = IsEqual();
    isMaxDepth.in[0] <== depth;
    isMaxDepth.in[1] <== MAX_DEPTH;

    // depth <= MAX_DEPTH.
    depthMatches + isMaxDepth.out === 1;

    for (var k = 0; k < 2; k++) {
        out[k] <== root[k] + isMaxDepth.out * nodeLimbs[MAX_DEPTH].out[k];
    }
}
