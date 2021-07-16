/*************************************************************************
 * Copyright (c) 2020-2021 Elichai Turkel                                *
 * Distributed under the CC0 software license, see the accompanying file *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "random.h"
#include "secp256k1.h"



int main(void) {
    unsigned char msg_hash[32] = {0}; /* This must be a hash of the message. otherwise ECDSA is easily broken. */
    unsigned char seckey[32];
    unsigned char randomize[32];
    unsigned char compressed_pubkey[33];
    unsigned char serialized_signature[64];
    size_t len;
    int is_signature_valid;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;
    /* The docs in secp256k1.h above the `secp256k1_ec_pubkey_create` function
     * say: "pointer to a context object, initialized for signing" And the docs
     * above the `secp256k1_ecdsa_verify` function say: "a secp256k1 context
     * object, initialized for verification" which is why we create a context
     * for both signing and verification with the SECP256K1_CONTEXT_SIGN and
     * SECP256K1_CONTEXT_VERIFY flags. */
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }
    /* Randomizing the context is recommended to protect against side-channel
     * leakage See `secp256k1_context_randomize` in secp256k1.h for more
     * information about it. This should never fail. */
    assert(secp256k1_context_randomize(ctx, randomize));

    /*** Key Generation ***/

    /* If the secret key is zero or out of range (bigger than secp256k1's
     * order), we try to sample a new key. Note that the probability of this
     * happening is negligible. */
    while (1) {
        if (!fill_random(seckey, sizeof(seckey))) {
            printf("Failed to generate randomness\n");
            return 1;
        }
        if (secp256k1_ec_seckey_verify(ctx, seckey)) {
            break;
        }
    }

    /* Public key creation using a valid context with a verified secret key should never fail */
    assert(secp256k1_ec_pubkey_create(ctx, &pubkey, seckey));

    /* Serialize the pubkey in a compressed form(33 bytes). Should always return 1. */
    len = sizeof(compressed_pubkey);
    assert(secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED));
    /* Should be the same size as the size of the output, because we passed a 33 bytes array. */
    assert(len == sizeof(compressed_pubkey));

    /*** Signing ***/

    /* Generate an ECDSA signature, note that even though here `msg_hash` is set
    * to zeros, it MUST contain a hash, otherwise ECDSA is easily broken.
    * `noncefp` and `ndata` allows you to pass a custom nonce function, passing
    * `NULL` will use the RFC-6979 safe default. Signing with a valid context,
    * verified secret key and the default nonce function should never fail. */
    assert(secp256k1_ecdsa_sign(ctx, &sig, msg_hash, seckey, NULL, NULL));

    /* Serialize the signature in a compact form. Should always return 1
     * according to the documentation in secp256k1.h. */
    assert(secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_signature, &sig));


    /*** Verification ***/

    /* Deserialize the signature. This will return 0 if the signature can't be parsed correctly. */
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, serialized_signature)) {
        printf("Failed parsing the signature\n");
        return 1;
    }

    /*** Verification ***/

    /* Deserialize the public key. This will return 0 if the public key can't be parsed correctly. */
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, compressed_pubkey, sizeof(compressed_pubkey))) {
        printf("Failed parsing the public key\n");
        return 1;
    }

    /* Verify a signature. This will return 1 if it's valid and 0 if it's not. */
    is_signature_valid = secp256k1_ecdsa_verify(ctx, &sig, msg_hash, &pubkey);

    printf("Is the signature valid? %s\n", is_signature_valid ? "true" : "false");
    printf("Secret Key: ");
    print_hex(seckey, sizeof(seckey));
    printf("Public Key: ");
    print_hex(compressed_pubkey, sizeof(compressed_pubkey));
    printf("Signature: ");
    print_hex(serialized_signature, sizeof(serialized_signature));


    /* This will clear everything from the context and free the memory */
    secp256k1_context_destroy(ctx);

    /* It's best practice to try to remove secrets from memory after using them.
     * This is done because some bugs can allow an attacker leak memory, for
     * example through out of bounds array access (see Heartbleed for example).
     * Hence, we overwrite the secret key buffer with zeros.
     *
     * TODO: Prevent these writes from being optimized out, as any good compiler
     * will remove any writes that aren't used. */
    memset(seckey, 0, sizeof(seckey));

    return 0;
}
