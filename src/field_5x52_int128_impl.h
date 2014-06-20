// Copyright (c) 2013 Pieter Wuille
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _SECP256K1_FIELD_INNER5X52_IMPL_H_
#define _SECP256K1_FIELD_INNER5X52_IMPL_H_

#include <stdint.h>

__extension__ typedef __int128 secp_int128_t;

void static inline secp256k1_fe_mul_inner(const uint64_t *a, const uint64_t *b, uint64_t *r) {
    secp_int128_t c = (secp_int128_t)a[0] * b[0];
    uint64_t t0 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0FFFFFFFFFFFFFE0
    c = c + (secp_int128_t)a[0] * b[1] +
            (secp_int128_t)a[1] * b[0];
    uint64_t t1 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 20000000000000BF
    c = c + (secp_int128_t)a[0] * b[2] +
            (secp_int128_t)a[1] * b[1] +
            (secp_int128_t)a[2] * b[0];
    uint64_t t2 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 30000000000001A0
    c = c + (secp_int128_t)a[0] * b[3] +
            (secp_int128_t)a[1] * b[2] +
            (secp_int128_t)a[2] * b[1] +
            (secp_int128_t)a[3] * b[0];
    uint64_t t3 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 4000000000000280
    c = c + (secp_int128_t)a[0] * b[4] +
            (secp_int128_t)a[1] * b[3] +
            (secp_int128_t)a[2] * b[2] +
            (secp_int128_t)a[3] * b[1] +
            (secp_int128_t)a[4] * b[0];
    uint64_t t4 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 320000000000037E
    c = c + (secp_int128_t)a[1] * b[4] +
            (secp_int128_t)a[2] * b[3] +
            (secp_int128_t)a[3] * b[2] +
            (secp_int128_t)a[4] * b[1];
    uint64_t t5 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 22000000000002BE
    c = c + (secp_int128_t)a[2] * b[4] +
            (secp_int128_t)a[3] * b[3] +
            (secp_int128_t)a[4] * b[2];
    uint64_t t6 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 12000000000001DE
    c = c + (secp_int128_t)a[3] * b[4] +
            (secp_int128_t)a[4] * b[3];
    uint64_t t7 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 02000000000000FE
    c = c + (secp_int128_t)a[4] * b[4];
    uint64_t t8 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 001000000000001E
    uint64_t t9 = (uint64_t)c;

    c = t0 + (secp_int128_t)t5 * 0x1000003D10ULL;
    t0 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0000001000003D10
    c = c + t1 + (secp_int128_t)t6 * 0x1000003D10ULL;
    t1 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0000001000003D10
    c = c + t2 + (secp_int128_t)t7 * 0x1000003D10ULL;
    r[2] = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0000001000003D10
    c = c + t3 + (secp_int128_t)t8 * 0x1000003D10ULL;
    r[3] = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0000001000003D10
    c = c + t4 + (secp_int128_t)t9 * 0x1000003D10ULL;
    r[4] = c & 0x0FFFFFFFFFFFFULL; c = c >> 48; // c max 000001000003D110
    c = t0 + (secp_int128_t)c * 0x1000003D1ULL;
    r[0] = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 1000008
    r[1] = t1 + (uint64_t)c;

}

void static inline secp256k1_fe_sqr_inner(const uint64_t *a, uint64_t *r) {
    secp_int128_t c = (secp_int128_t)a[0] * a[0];
    uint64_t t0 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0FFFFFFFFFFFFFE0
    c = c + (secp_int128_t)(a[0]*2) * a[1];
    uint64_t t1 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 20000000000000BF
    c = c + (secp_int128_t)(a[0]*2) * a[2] +
            (secp_int128_t)a[1] * a[1];
    uint64_t t2 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 30000000000001A0
    c = c + (secp_int128_t)(a[0]*2) * a[3] +
            (secp_int128_t)(a[1]*2) * a[2];
    uint64_t t3 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 4000000000000280
    c = c + (secp_int128_t)(a[0]*2) * a[4] +
            (secp_int128_t)(a[1]*2) * a[3] +
            (secp_int128_t)a[2] * a[2];
    uint64_t t4 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 320000000000037E
    c = c + (secp_int128_t)(a[1]*2) * a[4] +
            (secp_int128_t)(a[2]*2) * a[3];
    uint64_t t5 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 22000000000002BE
    c = c + (secp_int128_t)(a[2]*2) * a[4] +
            (secp_int128_t)a[3] * a[3];
    uint64_t t6 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 12000000000001DE
    c = c + (secp_int128_t)(a[3]*2) * a[4];
    uint64_t t7 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 02000000000000FE
    c = c + (secp_int128_t)a[4] * a[4];
    uint64_t t8 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 001000000000001E
    uint64_t t9 = (uint64_t)c;
    c = t0 + (secp_int128_t)t5 * 0x1000003D10ULL;
    t0 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0000001000003D10
    c = c + t1 + (secp_int128_t)t6 * 0x1000003D10ULL;
    t1 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0000001000003D10
    c = c + t2 + (secp_int128_t)t7 * 0x1000003D10ULL;
    r[2] = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0000001000003D10
    c = c + t3 + (secp_int128_t)t8 * 0x1000003D10ULL;
    r[3] = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0000001000003D10
    c = c + t4 + (secp_int128_t)t9 * 0x1000003D10ULL;
    r[4] = c & 0x0FFFFFFFFFFFFULL; c = c >> 48; // c max 000001000003D110
    c = t0 + (secp_int128_t)c * 0x1000003D1ULL;
    r[0] = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 1000008
    r[1] = t1 + (uint64_t)c;

}

#endif
