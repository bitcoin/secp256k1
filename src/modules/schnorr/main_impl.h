/**********************************************************************
 * Copyright (c) 2014-2015 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORR_MAIN
#define SECP256K1_MODULE_SCHNORR_MAIN

#include "include/secp256k1_schnorr.h"
#include "modules/schnorr/schnorr_impl.h"

static void secp256k1_schnorr_msghash_sha256(unsigned char *h32, const unsigned char *r32, const unsigned char *msg32) {
    secp256k1_sha256_t sha;
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, r32, 32);
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_finalize(&sha, h32);
}

static const unsigned char secp256k1_schnorr_algo16[17] = "Schnorr+SHA256  ";

int secp256k1_schnorr_sign(const secp256k1_context* ctx, unsigned char *sig64, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void *ndata) {
    secp256k1_scalar sec, nonce_mine;
    secp256k1_ge pubnonce_all;
    int ret = 0;
    int overflow = 0;
    unsigned int count = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(seckey != NULL);
    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_default;
    }

    secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    ret = !secp256k1_scalar_is_zero(&sec) && !overflow;
    while (ret) {
        unsigned char nonce32[32];
        ret = noncefp(nonce32, msg32, seckey, secp256k1_schnorr_algo16, (void*)ndata, count);
        if (!ret) {
            break;
        }
        ret = secp256k1_schnorr_nonces_set_b32(&ctx->ecmult_gen_ctx, &nonce_mine, &pubnonce_all, nonce32, NULL) &&
            secp256k1_schnorr_sig_sign(sig64, &sec, &nonce_mine, &pubnonce_all, secp256k1_schnorr_msghash_sha256, msg32);
        memset(nonce32, 0, 32);
        if (ret) {
            break;
        }
        count++;
    }
    if (!ret) {
        memset(sig64, 0, 64);
    }
    secp256k1_scalar_clear(&nonce_mine);
    secp256k1_scalar_clear(&sec);
    return ret;
}

int secp256k1_schnorr_verify(const secp256k1_context* ctx, const unsigned char *sig64, const unsigned char *msg32, const secp256k1_pubkey *pubkey) {
    secp256k1_ge q;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(pubkey != NULL);

    secp256k1_pubkey_load(ctx, &q, pubkey);
    return secp256k1_schnorr_sig_verify(&ctx->ecmult_ctx, sig64, &q, secp256k1_schnorr_msghash_sha256, msg32);
}

int secp256k1_schnorr_recover(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *sig64, const unsigned char *msg32) {
    secp256k1_ge q;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(pubkey != NULL);

    if (secp256k1_schnorr_sig_recover(&ctx->ecmult_ctx, sig64, &q, secp256k1_schnorr_msghash_sha256, msg32)) {
        secp256k1_pubkey_save(pubkey, &q);
        return 1;
    } else {
        memset(pubkey, 0, sizeof(*pubkey));
        return 0;
    }
}

static int secp256k1_schnorr_multisign_generate_nonces(const secp256k1_context* ctx, secp256k1_scalar* nonce_mine, secp256k1_ge *pubnonce_all, const secp256k1_ge *pubnonce_others, const unsigned char *msg32, const unsigned char *sec32, secp256k1_nonce_function noncefp, const void* ndata) {
    int ret;
    int count = 0;

    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_default;
    }

    while (1) {
        unsigned char nonce32[32];
        ret = noncefp(nonce32, msg32, sec32, secp256k1_schnorr_algo16, (void*)ndata, count);
        if (!ret) {
            break;
        }
        ret = secp256k1_schnorr_nonces_set_b32(&ctx->ecmult_gen_ctx, nonce_mine, pubnonce_all, nonce32, pubnonce_others);
        memset(nonce32, 0, 32);
        if (ret) {
            break;
        }
        count++;
    }

    if (!ret) {
        secp256k1_scalar_clear(nonce_mine);
    }
    return ret;
}

int secp256k1_schnorr_multisign_stage1(const secp256k1_context* ctx, unsigned char *stage1, const unsigned char *msg32, const unsigned char *sec32, secp256k1_nonce_function noncefp, const void* noncedata) {
    secp256k1_scalar nonce_mine;
    secp256k1_ge pubnonce_mine;
    unsigned char tmphash[32];
    secp256k1_sha256_t sha;
    int ret;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(sec32 != NULL);
    ARG_CHECK(stage1 != NULL);

    ret = secp256k1_schnorr_multisign_generate_nonces(ctx, &nonce_mine, &pubnonce_mine, NULL, msg32, sec32, noncefp, noncedata);
    secp256k1_scalar_clear(&nonce_mine);
    secp256k1_schnorr_ge_get_b32(stage1, &pubnonce_mine);
    secp256k1_fe_normalize(&pubnonce_mine.x);
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, stage1, 32);
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_finalize(&sha, tmphash);
    ret = ret & secp256k1_schnorr_sign(ctx, stage1 + 32, tmphash, sec32, noncefp, noncedata);

    if (!ret) {
        memset(stage1, 0, 96);
    }
    return ret;
}

int secp256k1_schnorr_multisign_stage2(const secp256k1_context* ctx, unsigned char *stage2, const unsigned char * const *other_stage1s, size_t num_others, const unsigned char *msg32, const secp256k1_pubkey * const *other_pubkeys, const unsigned char *sec32, secp256k1_nonce_function noncefp, const void* noncedata) {
    int ret = 1;
    int overflow = 0;
    secp256k1_scalar sec, nonce_mine;
    secp256k1_ge pubnonce_others;
    secp256k1_ge pubnonce_all;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(stage2 != NULL);
    if (num_others > 0) {
        ARG_CHECK(other_stage1s != NULL);
        ARG_CHECK(other_pubkeys != NULL);
        ARG_CHECK(other_stage1s[num_others - 1] != NULL);
        ARG_CHECK(other_pubkeys[num_others - 1] != NULL);
    }
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(sec32 != NULL);

    secp256k1_scalar_set_b32(&sec, sec32, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&sec)) {
        return 0;
    }

    if (num_others > 0) {
        secp256k1_gej pubnoncej_others;
        size_t n = 0;
        while (n < num_others) {
            secp256k1_ge tmppub;
            secp256k1_sha256_t sha;
            unsigned char tmphash[32];
            secp256k1_sha256_initialize(&sha);
            secp256k1_sha256_write(&sha, other_stage1s[n], 32);
            secp256k1_sha256_write(&sha, msg32, 32);
            secp256k1_sha256_finalize(&sha, tmphash);
            ret = ret & secp256k1_schnorr_verify(ctx, other_stage1s[n] + 32, tmphash, other_pubkeys[n]);
            ret = ret & secp256k1_schnorr_ge_set_b32(&tmppub, other_stage1s[n]);
            if (n) {
                secp256k1_gej_add_ge(&pubnoncej_others, &pubnoncej_others, &tmppub);
            } else {
                secp256k1_gej_set_ge(&pubnoncej_others, &tmppub);
            }
            n++;
        }
        if (ret) {
            secp256k1_ge_set_gej(&pubnonce_others, &pubnoncej_others);
        }
    }

    ret = ret & secp256k1_schnorr_multisign_generate_nonces(ctx, &nonce_mine, &pubnonce_all, num_others > 0 ? &pubnonce_others : NULL, msg32, sec32, noncefp, noncedata);
    ret = ret && secp256k1_schnorr_sig_sign(stage2, &sec, &nonce_mine, &pubnonce_all, secp256k1_schnorr_msghash_sha256, msg32);
    secp256k1_scalar_clear(&sec);
    secp256k1_scalar_clear(&nonce_mine);
    if (!ret) {
        memset(stage2, 0, 64);
    }
    return ret;
}

int secp256k1_schnorr_multisign_combine(const secp256k1_context* ctx, unsigned char *sig64, const unsigned char * const *stage2s, size_t n) {
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(n >= 1);
    ARG_CHECK(stage2s != NULL);
    ARG_CHECK(stage2s[n - 1] != NULL);
    return secp256k1_schnorr_sig_combine(sig64, n, stage2s);
}

#endif
