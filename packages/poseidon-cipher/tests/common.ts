import { Fr, Point, mulPointEscalar } from "@zk-kit/baby-jubjub"
import { deriveSecretScalar } from "@zk-kit/eddsa-poseidon"
import { poseidonPerm } from "@zk-kit/poseidon-cipher"
import { Circomkit } from "circomkit"
import { readFileSync } from "fs"
import path from "path"

const configFilePath = path.join(__dirname, "../circomkit.json")
const config = JSON.parse(readFileSync(configFilePath, "utf-8"))

// eslint-disable-next-line import/prefer-default-export
export const circomkit = new Circomkit({
    ...config,
    verbose: false
})

/**
 * Generates an Elliptic-Curve Diffie–Hellman (ECDH) shared key given a private
 * key and a public key.
 * @param privKey A private key generated using genPrivKey()
 * @param pubKey A public key generated using genPubKey()
 * @returns The ECDH shared key.
 */
export const genEcdhSharedKey = (privKey: Buffer | Uint8Array | string, pubKey: [bigint, bigint]): Point<bigint> => {
    const secretScalar = deriveSecretScalar(privKey)

    return mulPointEscalar(pubKey, secretScalar) as Point<bigint>
}

/**
 * Encrypts an already padded message while declaring a different plaintext
 * length in the initial state. `poseidonEncrypt` always pads with zeros, so
 * this is the only way to build a ciphertext whose padding words decrypt to
 * something other than zero while the authentication tag still matches.
 * @param message A message whose length is a multiple of 3.
 * @param length The plaintext length to encode in the initial state.
 * @param key The encryption key.
 * @param nonce The nonce.
 * @returns The ciphertext.
 */
export const poseidonEncryptWithLength = (
    message: bigint[],
    length: number,
    key: Point<bigint>,
    nonce: bigint
): bigint[] => {
    const two128 = Fr.e(BigInt("340282366920938463463374607431768211456"))

    let state = [Fr.zero, Fr.e(key[0]), Fr.e(key[1]), Fr.add(Fr.e(nonce), Fr.mul(Fr.e(BigInt(length)), two128))]

    const ciphertext: bigint[] = []

    for (let i = 0; i < message.length / 3; i += 1) {
        state = poseidonPerm(state)

        state[1] = Fr.add(state[1], Fr.e(message[i * 3]))
        state[2] = Fr.add(state[2], Fr.e(message[i * 3 + 1]))
        state[3] = Fr.add(state[3], Fr.e(message[i * 3 + 2]))

        ciphertext.push(state[1], state[2], state[3])
    }

    state = poseidonPerm(state)
    ciphertext.push(state[1])

    return ciphertext
}
