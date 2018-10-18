/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <string.h>

#include "include/secp256k1.h"
#include "include/secp256k1_aggsig.h"
#include "util.h"
#include "bench.h"

#define N_SIGNATURES	30

typedef struct {
    secp256k1_context *ctx;
    secp256k1_aggsig_context *aggctx;
    secp256k1_scratch_space *scratch;
    unsigned char seckeys[N_SIGNATURES][32];
    secp256k1_pubkey pubkeys[N_SIGNATURES];
    secp256k1_aggsig_partial_signature partials[N_SIGNATURES];
    unsigned char msg[32];
    unsigned char sig[64];
} bench_aggsig_t;

void bench_aggsig(void* arg) {
    size_t i;
    bench_aggsig_t *data = (bench_aggsig_t*) arg;
    for (i = 0; i < 2000; i++) {
        CHECK(secp256k1_aggsig_verify(data->ctx, data->scratch, data->sig, data->msg, data->pubkeys, N_SIGNATURES));
    }
}

void bench_aggsig_setup(void* arg) {
    size_t i;
    bench_aggsig_t *data = (bench_aggsig_t*) arg;
    for (i = 0; i < N_SIGNATURES; i++) {
        CHECK(secp256k1_aggsig_generate_nonce(data->ctx, data->aggctx, i));
    }
    for (i = 0; i < N_SIGNATURES; i++) {
        CHECK(secp256k1_aggsig_partial_sign(data->ctx, data->aggctx, &data->partials[i], data->msg, data->seckeys[i], i));
    }
    CHECK(secp256k1_aggsig_combine_signatures(data->ctx, data->aggctx, data->sig, data->partials, N_SIGNATURES));
}

int main(void) {
    size_t i;
    unsigned char seed[32] = "this'll do for a seed i guess.";
    bench_aggsig_t data;
    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    data.scratch = secp256k1_scratch_space_create(data.ctx, 10000, 25000);

    for (i = 0; i < N_SIGNATURES; i++) {
        memcpy(&data.seckeys[i], seed, 32);
        data.seckeys[i][0] += i;
        CHECK(secp256k1_ec_pubkey_create(data.ctx, &data.pubkeys[i], data.seckeys[i]));
    }
    data.aggctx = secp256k1_aggsig_context_create(data.ctx, data.pubkeys, N_SIGNATURES, seed);

    run_benchmark("aggsig_32", bench_aggsig, bench_aggsig_setup, NULL, &data, 1, 2000);

    secp256k1_aggsig_context_destroy(data.aggctx);
    secp256k1_scratch_space_destroy(data.scratch);
    secp256k1_context_destroy(data.ctx);
    return 0;
}
