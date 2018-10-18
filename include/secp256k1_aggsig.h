#ifndef _SECP256K1_AGGSIG_
# define _SECP256K1_AGGSIG_

# include "secp256k1.h"

# ifdef __cplusplus
extern "C" {
# endif

/** Opaque data structure that holds context for the aggregated signature state machine
 *
 *  During execution of an aggregated signature this context object will contain secret
 *  data. It MUST be destroyed by `secp256k1_aggsig_context_destroy` to erase this data
 *  before freeing it. Context objects are sized based on the number of signatures to
 *  aggregate, and can be reused for multiple signature runs, provided that each run
 *  aggregates the same number of signatures.
 *
 *  Destroying and recreating a context object is essentially just deallocating and
 *  reallocating memory, there is no expensive precomputation as there is with the general
 *  libsecp256k1 context.
 *
 *  Once a context object is created with `secp256k1_aggsig_context_create` the workflow
 *  is as follows.
 *
 *      1. For each index controlled by the user, use `secp256k1_aggsig_generate_nonce`
 *         to generate a public/private nonce pair for that index. [TODO export the
 *         public nonce for other users]
 *      2. [TODO import others' public nonces]
 *      3. For each index controlled by the user, use `secp256k1_aggsig_partial_sign`
 *         to generate a partial signature that should be distributed to all peers.
 */
typedef struct secp256k1_aggsig_context_struct secp256k1_aggsig_context;

/** Opaque data structure that holds a partial signature
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 32 bytes in size, and can be safely copied, moved.
 *  and transmitted as raw bytes.
 */
typedef struct {
    unsigned char data[32];
} secp256k1_aggsig_partial_signature;


/** Create an aggregated signature context object with a given size
 *
 *  Returns: a newly created context object.
 *  Args: ctx:  an existing context object (cannot be NULL)
 *  In:     pubkeys: public keys for each signature (cannot be NULL)
 *        n_pubkeys: number of public keys/signatures to aggregate
 *             seed: a 32-byte seed to use for the nonce-generating RNG (cannot be NULL)
 */
SECP256K1_API secp256k1_aggsig_context* secp256k1_aggsig_context_create(
    const secp256k1_context *ctx,
    const secp256k1_pubkey *pubkeys,
    size_t n_pubkeys,
    const unsigned char *seed
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_WARN_UNUSED_RESULT;


/** Destroy an aggregated signature context object. If passed NULL, is a no-op.
 *
 *  Args: aggctx:  an existing context object
 */
SECP256K1_API void secp256k1_aggsig_context_destroy(
    secp256k1_aggsig_context *aggctx
);

/** Generate a nonce pair for a single signature part in an aggregated signature
 *
 *  Returns: 1 on success
 *           0 if a nonce has already been generated for this index
 *  Args:    ctx: an existing context object, initialized for signing (cannot be NULL)
 *        aggctx: an aggsig context object (cannot be NULL)
 *  In:    index: which signature to generate a nonce for
 */
SECP256K1_API int secp256k1_aggsig_generate_nonce(
    const secp256k1_context* ctx,
    secp256k1_aggsig_context* aggctx,
    size_t index
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_WARN_UNUSED_RESULT;


/** Generate a single signature part in an aggregated signature
 *
 *  Returns: 1 on success, 0 on failure
 *  Args:    ctx: an existing context object, initialized for signing (cannot be NULL)
 *        aggctx: an aggsig context object (cannot be NULL)
 *  Out:   partial: the generated signature part (cannot be NULL)
 *  In:  msghash32: the message to sign (cannot be NULL)
 *        seckey32: the secret signing key (cannot be NULL)
 *           index: the index of this signature in the aggregate signature
 */
SECP256K1_API int secp256k1_aggsig_partial_sign(
    const secp256k1_context* ctx,
    secp256k1_aggsig_context* aggctx,
    secp256k1_aggsig_partial_signature *partial,
    const unsigned char *msghash32,
    const unsigned char *seckey32,
    size_t index
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_WARN_UNUSED_RESULT;


/** Aggregate multiple signature parts into a single aggregated signature
 *
 *  Returns: 1 on success, 0 on failure
 *  Args:    ctx: an existing context object, initialized for signing (cannot be NULL)
 *        aggctx: an aggsig context object (cannot be NULL)
 *  Out:     sig64: the completed signature (cannot be NULL)
 *  In:    partial: an array of partial signatures to aggregate (cannot be NULL)
 *          n_sigs: the number of partial signatures provided
 */
SECP256K1_API int secp256k1_aggsig_combine_signatures(
    const secp256k1_context* ctx,
    secp256k1_aggsig_context* aggctx,
    unsigned char *sig64,
    const secp256k1_aggsig_partial_signature *partial,
    size_t n_sigs
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_WARN_UNUSED_RESULT;


/** Verify an aggregate signature
 *
 *  Returns: 1 if the signature is valid, 0 if not
 *  Args:    ctx: an existing context object (cannot be NULL)
 *       scratch: a scratch space (cannot be NULL)
 *  In:    sig64: the signature to verify (cannot be NULL)
 *         msg32: the message that should be signed (cannot be NULL)
 *       pubkeys: array of public keys (cannot be NULL)
 *        n_keys: the number of public keys
 */
SECP256K1_API int secp256k1_aggsig_verify(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_pubkey *pubkeys,
    size_t n_pubkeys
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_WARN_UNUSED_RESULT;

# ifdef __cplusplus
}
# endif

#endif
