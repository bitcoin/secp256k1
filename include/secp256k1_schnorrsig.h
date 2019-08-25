#ifndef SECP256K1_SCHNORRSIG_H
#define SECP256K1_SCHNORRSIG_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** This module implements a variant of Schnorr signatures compliant with
 * BIP-schnorr
 * (https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki).
 */

/** Opaque data structure that holds a parsed Schnorr signature.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage, transmission, or
 *  comparison, use the `secp256k1_schnorrsig_serialize` and
 *  `secp256k1_schnorrsig_parse` functions.
 */
typedef struct {
    unsigned char data[64];
} secp256k1_schnorrsig;

/** Serialize a Schnorr signature.
 *
 *  Returns: 1
 *  Args:    ctx: a secp256k1 context object
 *  Out:   out64: pointer to a 64-byte array to store the serialized signature
 *  In:      sig: pointer to the signature
 *
 *  See secp256k1_schnorrsig_parse for details about the encoding.
 */
SECP256K1_API int secp256k1_schnorrsig_serialize(
    const secp256k1_context* ctx,
    unsigned char *out64,
    const secp256k1_schnorrsig* sig
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Parse a Schnorr signature.
 *
 *  Returns: 1 when the signature could be parsed, 0 otherwise.
 *  Args:    ctx: a secp256k1 context object
 *  Out:     sig: pointer to a signature object
 *  In:     in64: pointer to the 64-byte signature to be parsed
 *
 * The signature is serialized in the form R||s, where R is a 32-byte public
 * key (x-coordinate only; the y-coordinate is considered to be the unique
 * y-coordinate satisfying the curve equation that is a quadratic residue)
 * and s is a 32-byte big-endian scalar.
 *
 * After the call, sig will always be initialized. If parsing failed or the
 * encoded numbers are out of range, signature validation with it is
 * guaranteed to fail for every message and public key.
 */
SECP256K1_API int secp256k1_schnorrsig_parse(
    const secp256k1_context* ctx,
    secp256k1_schnorrsig* sig,
    const unsigned char *in64
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Anti Nonce Sidechannel Protocol
 *
 *  The next functions can be used to prevent a signing device from exfiltrating the secret signing
 *  keys through biased signature nonces. The general idea is that a host provides additional
 *  randomness to the signing device client and the client commits to the randomness in the nonce
 *  using sign-to-contract.
 *  In order to make the randomness unpredictable, the host and client must engage in a
 *  commit-reveal protocol as follows:
 *  1. The host draws the randomness, commits to it with the `anti_nonce_sidechan_host_commit`
 *     function and sends the commitment to the client.
 *  2. The client commits to its sign-to-contract original nonce (which is the nonce without the
 *     sign-to-contract tweak) using the hosts commitment by calling the
 *     `secp256k1_schnorrsig_anti_nonce_sidechan_client_commit` function. The client sends the
 *     resulting commitment to the host
 *  3. The host replies with the randomness generated in step 1.
 *  4. The client signs with `schnorrsig_sign` using the host provided randomness as `s2c_data` and
 *     sends the signature and opening to the host.
 *  5. The host checks that the signature contains an sign-to-contract commitment to the randomness
 *     by calling `secp256k1_schnorrsig_anti_nonce_sidechan_host_verify` with the client's
 *     commitment from step 2 and the signature and opening received in step 4. If verification does
 *     not succeed, the protocol failed and can be restarted.
 *
 *  Rationale:
 *      - The reason for having a host commitment is to allow the client to derive a unique nonce
 *        for every host randomness. Otherwise the client would reuse the original nonce and thereby
 *        leaking the secret key to the host.
 *      - The client does not need to check that the host commitment matches the host's randomness.
 *        That's because the client derives its nonce using the hosts randomness commitment. If the
 *        commitment doesn't match then the client will derive a different original nonce and the
 *        only result will be that the host is not able to verify the sign-to-contract commitment.
 *        Therefore, the client does not need to maintain state about the progress of the protocol.
 */

/** Create a randomness commitment on the host as part of the Anti Nonce Sidechannel Protocol.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:              ctx: pointer to a context object (cannot be NULL)
 *  Out: rand_commitment32: pointer to 32-byte array to store the returned commitment (cannot be NULL)
 *  In:             rand32: the 32-byte randomness to commit to (cannot be NULL)
 */
SECP256K1_API int secp256k1_schnorrsig_anti_nonce_sidechan_host_commit(
    secp256k1_context *ctx,
    unsigned char *rand_commitment32,
    const unsigned char *rand32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Compute commitment on the client as part of the Anti Nonce Sidechannel Protocol.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:           ctx: pointer to a context object (cannot be NULL)
 *  Out:  client_commit: pointer to a pubkey where the clients public nonce will be
 *                       placed. This is the public nonce before doing the
 *                       sign-to-contract commitment to the hosts randomness (cannot
 *                       be NULL)
 *  In:           msg32: the 32-byte message hash to be signed (cannot be NULL)
 *             seckey32: the 32-byte secret key used for signing (cannot be NULL)
 *    rand_commitment32: the 32-byte randomness commitment from the host (cannot be NULL)
 */
SECP256K1_API int secp256k1_schnorrsig_anti_nonce_sidechan_client_commit(
    secp256k1_context *ctx,
    secp256k1_pubkey *client_commit,
    const unsigned char *msg32,
    const unsigned char *seckey32,
    unsigned char *rand_commitment32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Verify that a clients signature contains the hosts randomness as part of the Anti
 *  Nonce Sidechannel Protocol. Does not verify the signature itself.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  In:           sig: pointer to the signature whose randomness should be verified
 *                     (cannot be NULL)
 *             rand32: pointer to the 32-byte randomness from the host which should
 *                     be included by the signature (cannot be NULL)
 *            opening: pointer to the opening produced by the client when signing
 *                     with `rand32` as `s2c_data` (cannot be NULL)
 *      client_commit: pointer to the client's commitment created in
 *                     `secp256k1_schnorrsig_anti_nonce_sidechan_client_commit`
 *                     (cannot be NULL)
 */
SECP256K1_API int secp256k1_schnorrsig_anti_nonce_sidechan_host_verify(
    secp256k1_context *ctx,
    const secp256k1_schnorrsig *sig,
    const unsigned char *rand32,
    const secp256k1_s2c_opening *opening,
    const secp256k1_pubkey *client_commit
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Create a Schnorr signature.
 *
 * Returns 1 on success, 0 on failure.
 *  Args:    ctx: pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:     sig: pointer to the returned signature (cannot be NULL)
 *   s2c_opening: pointer to an secp256k1_s2c_opening structure which can be
 *                NULL but is required to be not NULL if this signature creates
 *                a sign-to-contract commitment (i.e. the `s2c_data` argument
 *                is not NULL).
 *  In:    msg32: the 32-byte message hash being signed (cannot be NULL)
 *        seckey: pointer to a 32-byte secret key (cannot be NULL)
 *    s2c_data32: pointer to a 32-byte data to create an optional
 *                sign-to-contract commitment to if not NULL (can be NULL).
 *       noncefp: pointer to a nonce generation function. If NULL, secp256k1_nonce_function_bipschnorr is used
 *         ndata: pointer to arbitrary data used by the nonce generation function. If s2c_data is not NULL,
 *                nust be NULL or `secp256k1_nonce_function_bipschnorr` (can be NULL)
 */
SECP256K1_API int secp256k1_schnorrsig_sign(
    const secp256k1_context* ctx,
    secp256k1_schnorrsig *sig,
    secp256k1_s2c_opening *s2c_opening,
    const unsigned char *msg32,
    const unsigned char *seckey,
    const unsigned char *s2c_data32,
    secp256k1_nonce_function noncefp,
    void *ndata
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Verify a Schnorr signature.
 *
 *  Returns: 1: correct signature
 *           0: incorrect or unparseable signature
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *  In:      sig: the signature being verified (cannot be NULL)
 *         msg32: the 32-byte message being verified (cannot be NULL)
 *        pubkey: pointer to a public key to verify with (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorrsig_verify(
    const secp256k1_context* ctx,
    const secp256k1_schnorrsig *sig,
    const unsigned char *msg32,
    const secp256k1_pubkey *pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Verifies a set of Schnorr signatures.
 *
 * Returns 1 if all succeeded, 0 otherwise. In particular, returns 1 if n_sigs is 0.
 *
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *       scratch: scratch space used for the multiexponentiation
 *  In:      sig: array of signatures, or NULL if there are no signatures
 *         msg32: array of messages, or NULL if there are no signatures
 *            pk: array of public keys, or NULL if there are no signatures
 *        n_sigs: number of signatures in above arrays. Must be smaller than
 *                2^31 and smaller than half the maximum size_t value. Must be 0
 *                if above arrays are NULL.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorrsig_verify_batch(
    const secp256k1_context* ctx,
    secp256k1_scratch_space *scratch,
    const secp256k1_schnorrsig *const *sig,
    const unsigned char *const *msg32,
    const secp256k1_pubkey *const *pk,
    size_t n_sigs
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Verify a sign-to-contract commitment.
 *
 *  Returns: 1: the signature contains a commitment to data32
 *           0: incorrect opening
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *  In:      sig: the signature containing the sign-to-contract commitment (cannot be NULL)
 *        data32: the 32-byte data that was committed to (cannot be NULL)
 *       opening: pointer to the opening created during signing (cannot be NULL)
 */
SECP256K1_API int secp256k1_schnorrsig_verify_s2c_commit(
    const secp256k1_context* ctx,
    const secp256k1_schnorrsig *sig,
    const unsigned char *data32,
    const secp256k1_s2c_opening *opening
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SCHNORRSIG_H */
