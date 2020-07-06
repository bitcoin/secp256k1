/**********************************************************************
 * Copyright (c) 2017 Tomas van der Wansem                            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include "include/secp256k1.h"
#include "include/secp256k1_multiset.h"
#include "util.h"
#include "bench.h"

secp256k1_context *ctx;

#define UNUSED(x) (void)(x)

void bench_multiset(void* arg) {
    static int it=0;
    unsigned n,m;
    unsigned char result[32];
    secp256k1_multiset multiset;

    UNUSED(arg);
    secp256k1_multiset_init(ctx, &multiset);

    for (m=0; m < 100000; m++)
    {
        unsigned char buf[32*3];
        secp256k1_multiset x;

        for(n = 0; n < sizeof(buf); n++)
            buf[n] = it++;

        secp256k1_multiset_add(ctx, &x, buf, sizeof(buf));

    }

    secp256k1_multiset_finalize(ctx, result, &multiset);
}

void bench_multiset_setup(void* arg) {
    UNUSED(arg);
}

int main(void) {

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    run_benchmark("ecdsa_multiset", bench_multiset, bench_multiset_setup, NULL, NULL, 10, 20);

    secp256k1_context_destroy(ctx);
    return 0;
}
