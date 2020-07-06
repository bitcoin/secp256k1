/**********************************************************************
 * Copyright (c) 2017 Tomas van der Wansem                            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MULTISET_TESTS_
#define _SECP256K1_MODULE_MULTISET_TESTS_


#include "include/secp256k1.h"
#include "include/secp256k1_multiset.h"
#include "util.h"
#include "testrand.h"

#define DATALEN   64*3
#define DATACOUNT 100


#define CHECK_EQUAL(a,b) { \
    unsigned char hash1[32]; \
    unsigned char hash2[32]; \
    secp256k1_multiset_finalize(ctx, hash1, (a)); \
    secp256k1_multiset_finalize(ctx, hash2, (b)); \
    CHECK(memcmp(hash1,hash2,sizeof(hash1))==0); \
}

#define CHECK_NOTEQUAL(a,b) { \
    unsigned char hash1[32]; \
    unsigned char hash2[32]; \
    secp256k1_multiset_finalize(ctx, hash1, (a)); \
    secp256k1_multiset_finalize(ctx, hash2, (b)); \
    CHECK(memcmp(hash1,hash2,sizeof(hash1))!=0); \
}

static unsigned char data[DATACOUNT][DATALEN];

/* create random data */
static void initdata(void) {
    int n,m;
    for(n=0; n < DATACOUNT; n++) {
        for(m=0; m < DATALEN/4; m++) {
            ((uint32_t*) data[n])[m] = secp256k1_rand32();
        }

    }
}

void test_unordered(void) {

    secp256k1_multiset empty, r1,r2,r3;

    secp256k1_multiset_init(ctx, &empty);
    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);

    secp256k1_multiset_add(ctx, &r1, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[1], DATALEN);



    CHECK_NOTEQUAL(&r1,&r2);
    secp256k1_multiset_add(ctx, &r1, data[1], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[0], DATALEN);
    CHECK_EQUAL(&r1,&r2);

    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);

    CHECK_EQUAL(&r1,&r2);


    secp256k1_multiset_add(ctx, &r1, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r1, data[1], DATALEN);
    secp256k1_multiset_add(ctx, &r1, data[2], DATALEN);

    secp256k1_multiset_add(ctx, &r2, data[2], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[1], DATALEN);

    secp256k1_multiset_add(ctx, &r3, data[1], DATALEN);
    secp256k1_multiset_add(ctx, &r3, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r3, data[2], DATALEN);


    CHECK_EQUAL(&r1,&r2);
    CHECK_EQUAL(&r1,&r3);

    secp256k1_multiset_combine(ctx, &r3, &empty);
    CHECK_EQUAL(&r1,&r3);
    secp256k1_multiset_combine(ctx, &r3, &r2);
    CHECK_NOTEQUAL(&r1,&r3);

}

void test_combine(void) {

    secp256k1_multiset empty, r1,r2,r3;

    secp256k1_multiset_init(ctx, &empty);
    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);

    secp256k1_multiset_add(ctx, &r1, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[1], DATALEN);



    CHECK_NOTEQUAL(&r1,&r2);
    secp256k1_multiset_add(ctx, &r1, data[1], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[0], DATALEN);
    CHECK_EQUAL(&r1,&r2);

    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);

    CHECK_EQUAL(&r1,&r2);


    secp256k1_multiset_add(ctx, &r1, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r1, data[1], DATALEN);
    secp256k1_multiset_add(ctx, &r1, data[2], DATALEN);

    secp256k1_multiset_add(ctx, &r2, data[2], DATALEN);
    secp256k1_multiset_add(ctx, &r3, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r3, data[1], DATALEN);
    secp256k1_multiset_combine(ctx, &r2, &r3);
    CHECK_EQUAL(&r1,&r2);

    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);
    secp256k1_multiset_add(ctx, &r2, data[2], DATALEN);
    secp256k1_multiset_add(ctx, &r2, data[0], DATALEN);
    secp256k1_multiset_add(ctx, &r3, data[1], DATALEN);
    secp256k1_multiset_combine(ctx, &r2, &r3);
    CHECK_EQUAL(&r1,&r2);


    secp256k1_multiset_combine(ctx, &r2, &empty);
    CHECK_EQUAL(&r1,&r2);
    secp256k1_multiset_combine(ctx, &r2, &r1);
    CHECK_NOTEQUAL(&r1,&r2);

}


void test_remove(void) {

    secp256k1_multiset empty, r1,r2,r3;

    secp256k1_multiset_init(ctx, &empty);
    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);

    CHECK_EQUAL(&r1,&r2);

    secp256k1_multiset_add   (ctx, &r1, data[0], DATALEN);
    secp256k1_multiset_add   (ctx, &r1, data[1], DATALEN);
    secp256k1_multiset_add   (ctx, &r1, data[3], DATALEN);
    secp256k1_multiset_add   (ctx, &r1, data[9], DATALEN);
    secp256k1_multiset_add   (ctx, &r1, data[8], DATALEN);

    secp256k1_multiset_add   (ctx, &r2, data[1], DATALEN);
    secp256k1_multiset_add   (ctx, &r2, data[9], DATALEN);
    secp256k1_multiset_add   (ctx, &r2, data[11], DATALEN);
    secp256k1_multiset_add   (ctx, &r2, data[10], DATALEN);
    secp256k1_multiset_add   (ctx, &r2, data[0], DATALEN);
    secp256k1_multiset_remove(ctx, &r2, data[10], DATALEN);
    secp256k1_multiset_add   (ctx, &r2, data[3], DATALEN);
    secp256k1_multiset_add   (ctx, &r2, data[8], DATALEN);
    secp256k1_multiset_remove(ctx, &r2, data[11], DATALEN);

    secp256k1_multiset_add   (ctx, &r3, data[9], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[15], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[15], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[1], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[9], DATALEN);
    secp256k1_multiset_remove(ctx, &r3, data[15], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[0], DATALEN);
    secp256k1_multiset_remove(ctx, &r3, data[15], DATALEN);
    secp256k1_multiset_remove(ctx, &r3, data[9], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[3], DATALEN);
    secp256k1_multiset_add   (ctx, &r3, data[8], DATALEN);

    CHECK_EQUAL(&r1,&r2);
    CHECK_EQUAL(&r1,&r3);
    CHECK_NOTEQUAL(&r1,&empty);

    secp256k1_multiset_remove(ctx, &r3, data[8], DATALEN);
    CHECK_NOTEQUAL(&r1,&r3);

    secp256k1_multiset_remove(ctx, &r2, data[0], DATALEN);
    secp256k1_multiset_remove(ctx, &r2, data[9], DATALEN);
    secp256k1_multiset_remove(ctx, &r2, data[8], DATALEN);
    secp256k1_multiset_remove(ctx, &r2, data[1], DATALEN);
    secp256k1_multiset_remove(ctx, &r2, data[3], DATALEN);

    CHECK_EQUAL(&r2,&empty);


}


void test_empty(void) {
    secp256k1_multiset empty, r1,r2;

    secp256k1_multiset_init(ctx, &empty);
    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);

    CHECK_EQUAL(&empty,&r1);

    /* empty + empty = empty */
    secp256k1_multiset_combine(ctx, &r1, &r2);
    CHECK_EQUAL(&empty, &r1);


}

void run_multiset_tests(void) {

    initdata();


    test_unordered();
    test_combine();
    test_remove();
    test_empty();

}

#endif
