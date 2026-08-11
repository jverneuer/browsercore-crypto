/**
 * The ML-KEM-768 backend contract (FIPS 203, formerly Kyber).
 *
 * Higher layers depend on this interface — never on a concrete implementation
 * — so the post-quantum KEM backend is replaceable (Node, WebCrypto, HSM, test
 * double). The implementation provides the three Key Encapsulation Mechanism
 * primitives: key generation, encapsulation (client side), and decapsulation
 * (server side). All inputs and outputs are raw byte arrays matching the FIPS
 * 203 parameter-set sizes — no ASN.1/DER container encoding.
 */

import type { MLKEM768Encapsulation, MLKEM768KeyPair } from "../types.js";

/**
 * ML-KEM-768 KEM primitives for TLS 1.3 hybrid key exchange.
 *
 * Implementations generate an encapsulation/decapsulation key pair, run the
 * client-side encapsulation (producing a ciphertext + shared secret), and the
 * server-side decapsulation (recovering the shared secret from a ciphertext).
 */
export interface MlKem768Backend {
    /** Generate an ML-KEM-768 key pair. */
    generateKeyPair(): MLKEM768KeyPair;
    /**
     * Encapsulate a shared secret under the peer's encapsulation (public) key.
     * The client side of the KEM: produces a ciphertext to send and the shared
     * secret to feed into the key schedule.
     */
    encapsulate(publicKey: Uint8Array): MLKEM768Encapsulation;
    /**
     * Decapsulate the shared secret from a ciphertext using the local
     * decapsulation (secret) key. The server side of the KEM.
     */
    decapsulate(secretKey: Uint8Array, ciphertext: Uint8Array): Uint8Array;
}
