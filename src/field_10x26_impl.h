/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_FIELD_REPR_IMPL_H
#define SECP256K1_FIELD_REPR_IMPL_H

#include "util.h"
#include "field.h"
#include "modinv32_impl.h"

#ifdef VERIFY
static void secp256k1_fe_verify(const secp256k1_fe *a) {
    const uint32_t *d = a->n;
    int m = a->normalized ? 1 : 2 * a->magnitude, r = 1;
    r &= (d[0] <= 0x3FFFFFFUL * m);
    r &= (d[1] <= 0x3FFFFFFUL * m);
    r &= (d[2] <= 0x3FFFFFFUL * m);
    r &= (d[3] <= 0x3FFFFFFUL * m);
    r &= (d[4] <= 0x3FFFFFFUL * m);
    r &= (d[5] <= 0x3FFFFFFUL * m);
    r &= (d[6] <= 0x3FFFFFFUL * m);
    r &= (d[7] <= 0x3FFFFFFUL * m);
    r &= (d[8] <= 0x3FFFFFFUL * m);
    r &= (d[9] <= 0x03FFFFFUL * m);
    r &= (a->magnitude >= 0);
    r &= (a->magnitude <= 32);
    if (a->normalized) {
        r &= (a->magnitude <= 1);
        if (r && (d[9] == 0x03FFFFFUL)) {
            uint32_t mid = d[8] & d[7] & d[6] & d[5] & d[4] & d[3] & d[2];
            if (mid == 0x3FFFFFFUL) {
                r &= ((d[1] + 0x40UL + ((d[0] + 0x3D1UL) >> 26)) <= 0x3FFFFFFUL);
            }
        }
    }
    VERIFY_CHECK(r == 1);
}
#endif

static void secp256k1_fe_normalize(secp256k1_fe *r) {
    uint32_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4],
             t5 = r->n[5], t6 = r->n[6], t7 = r->n[7], t8 = r->n[8], t9 = r->n[9];

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    uint32_t m;
    uint32_t x = t9 >> 22; t9 &= 0x03FFFFFUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL; m = t2;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL; m &= t3;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL; m &= t4;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL; m &= t5;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL; m &= t6;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL; m &= t7;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL; m &= t8;

    /* ... except for a possible carry at bit 22 of t9 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t9 >> 23 == 0);

    /* At most a single final reduction is needed; check if the value is >= the field characteristic */
    x = (t9 >> 22) | ((t9 == 0x03FFFFFUL) & (m == 0x3FFFFFFUL)
        & ((t1 + 0x40UL + ((t0 + 0x3D1UL) >> 26)) > 0x3FFFFFFUL));

    /* Apply the final reduction (for constant-time behaviour, we do it always) */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL;

    /* If t9 didn't carry to bit 22 already, then it should have after any final reduction */
    VERIFY_CHECK(t9 >> 22 == x);

    /* Mask off the possible multiple of 2^256 from the final reduction */
    t9 &= 0x03FFFFFUL;

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;
    r->n[5] = t5; r->n[6] = t6; r->n[7] = t7; r->n[8] = t8; r->n[9] = t9;

#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_normalize_weak(secp256k1_fe *r) {
    uint32_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4],
             t5 = r->n[5], t6 = r->n[6], t7 = r->n[7], t8 = r->n[8], t9 = r->n[9];

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    uint32_t x = t9 >> 22; t9 &= 0x03FFFFFUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL;

    /* ... except for a possible carry at bit 22 of t9 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t9 >> 23 == 0);

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;
    r->n[5] = t5; r->n[6] = t6; r->n[7] = t7; r->n[8] = t8; r->n[9] = t9;

#ifdef VERIFY
    r->magnitude = 1;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_normalize_var(secp256k1_fe *r) {
    uint32_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4],
             t5 = r->n[5], t6 = r->n[6], t7 = r->n[7], t8 = r->n[8], t9 = r->n[9];

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    uint32_t m;
    uint32_t x = t9 >> 22; t9 &= 0x03FFFFFUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL; m = t2;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL; m &= t3;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL; m &= t4;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL; m &= t5;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL; m &= t6;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL; m &= t7;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL; m &= t8;

    /* ... except for a possible carry at bit 22 of t9 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t9 >> 23 == 0);

    /* At most a single final reduction is needed; check if the value is >= the field characteristic */
    x = (t9 >> 22) | ((t9 == 0x03FFFFFUL) & (m == 0x3FFFFFFUL)
        & ((t1 + 0x40UL + ((t0 + 0x3D1UL) >> 26)) > 0x3FFFFFFUL));

    if (x) {
        t0 += 0x3D1UL; t1 += (x << 6);
        t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL;
        t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL;
        t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL;
        t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL;
        t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL;
        t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL;
        t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL;
        t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL;
        t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL;

        /* If t9 didn't carry to bit 22 already, then it should have after any final reduction */
        VERIFY_CHECK(t9 >> 22 == x);

        /* Mask off the possible multiple of 2^256 from the final reduction */
        t9 &= 0x03FFFFFUL;
    }

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;
    r->n[5] = t5; r->n[6] = t6; r->n[7] = t7; r->n[8] = t8; r->n[9] = t9;

#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
    secp256k1_fe_verify(r);
#endif
}

static int secp256k1_fe_normalizes_to_zero(const secp256k1_fe *r) {
    uint32_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4],
             t5 = r->n[5], t6 = r->n[6], t7 = r->n[7], t8 = r->n[8], t9 = r->n[9];

    /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
    uint32_t z0, z1;

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    uint32_t x = t9 >> 22; t9 &= 0x03FFFFFUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL; t1 += (x << 6);
    t1 += (t0 >> 26); t0 &= 0x3FFFFFFUL; z0  = t0; z1  = t0 ^ 0x3D0UL;
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL; z0 |= t1; z1 &= t1 ^ 0x40UL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL; z0 |= t2; z1 &= t2;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL; z0 |= t3; z1 &= t3;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL; z0 |= t4; z1 &= t4;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL; z0 |= t5; z1 &= t5;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL; z0 |= t6; z1 &= t6;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL; z0 |= t7; z1 &= t7;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL; z0 |= t8; z1 &= t8;
                                         z0 |= t9; z1 &= t9 ^ 0x3C00000UL;

    /* ... except for a possible carry at bit 22 of t9 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t9 >> 23 == 0);

    return (z0 == 0) | (z1 == 0x3FFFFFFUL);
}

static int secp256k1_fe_normalizes_to_zero_var(const secp256k1_fe *r) {
    uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
    uint32_t z0, z1;
    uint32_t x;

    t0 = r->n[0];
    t9 = r->n[9];

    /* Reduce t9 at the start so there will be at most a single carry from the first pass */
    x = t9 >> 22;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x3D1UL;

    /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
    z0 = t0 & 0x3FFFFFFUL;
    z1 = z0 ^ 0x3D0UL;

    /* Fast return path should catch the majority of cases */
    if ((z0 != 0UL) & (z1 != 0x3FFFFFFUL)) {
        return 0;
    }

    t1 = r->n[1];
    t2 = r->n[2];
    t3 = r->n[3];
    t4 = r->n[4];
    t5 = r->n[5];
    t6 = r->n[6];
    t7 = r->n[7];
    t8 = r->n[8];

    t9 &= 0x03FFFFFUL;
    t1 += (x << 6);

    t1 += (t0 >> 26);
    t2 += (t1 >> 26); t1 &= 0x3FFFFFFUL; z0 |= t1; z1 &= t1 ^ 0x40UL;
    t3 += (t2 >> 26); t2 &= 0x3FFFFFFUL; z0 |= t2; z1 &= t2;
    t4 += (t3 >> 26); t3 &= 0x3FFFFFFUL; z0 |= t3; z1 &= t3;
    t5 += (t4 >> 26); t4 &= 0x3FFFFFFUL; z0 |= t4; z1 &= t4;
    t6 += (t5 >> 26); t5 &= 0x3FFFFFFUL; z0 |= t5; z1 &= t5;
    t7 += (t6 >> 26); t6 &= 0x3FFFFFFUL; z0 |= t6; z1 &= t6;
    t8 += (t7 >> 26); t7 &= 0x3FFFFFFUL; z0 |= t7; z1 &= t7;
    t9 += (t8 >> 26); t8 &= 0x3FFFFFFUL; z0 |= t8; z1 &= t8;
                                         z0 |= t9; z1 &= t9 ^ 0x3C00000UL;

    /* ... except for a possible carry at bit 22 of t9 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t9 >> 23 == 0);

    return (z0 == 0) | (z1 == 0x3FFFFFFUL);
}

SECP256K1_INLINE static void secp256k1_fe_set_int(secp256k1_fe *r, int a) {
    r->n[0] = a;
    r->n[1] = r->n[2] = r->n[3] = r->n[4] = r->n[5] = r->n[6] = r->n[7] = r->n[8] = r->n[9] = 0;
#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
    secp256k1_fe_verify(r);
#endif
}

SECP256K1_INLINE static int secp256k1_fe_is_zero(const secp256k1_fe *a) {
    const uint32_t *t = a->n;
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    secp256k1_fe_verify(a);
#endif
    return (t[0] | t[1] | t[2] | t[3] | t[4] | t[5] | t[6] | t[7] | t[8] | t[9]) == 0;
}

SECP256K1_INLINE static int secp256k1_fe_is_odd(const secp256k1_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    secp256k1_fe_verify(a);
#endif
    return a->n[0] & 1;
}

SECP256K1_INLINE static void secp256k1_fe_clear(secp256k1_fe *a) {
    int i;
#ifdef VERIFY
    a->magnitude = 0;
    a->normalized = 1;
#endif
    for (i=0; i<10; i++) {
        a->n[i] = 0;
    }
}

static int secp256k1_fe_cmp_var(const secp256k1_fe *a, const secp256k1_fe *b) {
    int i;
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    VERIFY_CHECK(b->normalized);
    secp256k1_fe_verify(a);
    secp256k1_fe_verify(b);
#endif
    for (i = 9; i >= 0; i--) {
        if (a->n[i] > b->n[i]) {
            return 1;
        }
        if (a->n[i] < b->n[i]) {
            return -1;
        }
    }
    return 0;
}

static int secp256k1_fe_set_b32(secp256k1_fe *r, const unsigned char *a) {
    int ret;
    r->n[0] = (uint32_t)a[31] | ((uint32_t)a[30] << 8) | ((uint32_t)a[29] << 16) | ((uint32_t)(a[28] & 0x3) << 24);
    r->n[1] = (uint32_t)((a[28] >> 2) & 0x3f) | ((uint32_t)a[27] << 6) | ((uint32_t)a[26] << 14) | ((uint32_t)(a[25] & 0xf) << 22);
    r->n[2] = (uint32_t)((a[25] >> 4) & 0xf) | ((uint32_t)a[24] << 4) | ((uint32_t)a[23] << 12) | ((uint32_t)(a[22] & 0x3f) << 20);
    r->n[3] = (uint32_t)((a[22] >> 6) & 0x3) | ((uint32_t)a[21] << 2) | ((uint32_t)a[20] << 10) | ((uint32_t)a[19] << 18);
    r->n[4] = (uint32_t)a[18] | ((uint32_t)a[17] << 8) | ((uint32_t)a[16] << 16) | ((uint32_t)(a[15] & 0x3) << 24);
    r->n[5] = (uint32_t)((a[15] >> 2) & 0x3f) | ((uint32_t)a[14] << 6) | ((uint32_t)a[13] << 14) | ((uint32_t)(a[12] & 0xf) << 22);
    r->n[6] = (uint32_t)((a[12] >> 4) & 0xf) | ((uint32_t)a[11] << 4) | ((uint32_t)a[10] << 12) | ((uint32_t)(a[9] & 0x3f) << 20);
    r->n[7] = (uint32_t)((a[9] >> 6) & 0x3) | ((uint32_t)a[8] << 2) | ((uint32_t)a[7] << 10) | ((uint32_t)a[6] << 18);
    r->n[8] = (uint32_t)a[5] | ((uint32_t)a[4] << 8) | ((uint32_t)a[3] << 16) | ((uint32_t)(a[2] & 0x3) << 24);
    r->n[9] = (uint32_t)((a[2] >> 2) & 0x3f) | ((uint32_t)a[1] << 6) | ((uint32_t)a[0] << 14);

    ret = !((r->n[9] == 0x3FFFFFUL) & ((r->n[8] & r->n[7] & r->n[6] & r->n[5] & r->n[4] & r->n[3] & r->n[2]) == 0x3FFFFFFUL) & ((r->n[1] + 0x40UL + ((r->n[0] + 0x3D1UL) >> 26)) > 0x3FFFFFFUL));
#ifdef VERIFY
    r->magnitude = 1;
    if (ret) {
        r->normalized = 1;
        secp256k1_fe_verify(r);
    } else {
        r->normalized = 0;
    }
#endif
    return ret;
}

/** Convert a field element to a 32-byte big endian value. Requires the input to be normalized */
static void secp256k1_fe_get_b32(unsigned char *r, const secp256k1_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    secp256k1_fe_verify(a);
#endif
    r[0] = (a->n[9] >> 14) & 0xff;
    r[1] = (a->n[9] >> 6) & 0xff;
    r[2] = ((a->n[9] & 0x3F) << 2) | ((a->n[8] >> 24) & 0x3);
    r[3] = (a->n[8] >> 16) & 0xff;
    r[4] = (a->n[8] >> 8) & 0xff;
    r[5] = a->n[8] & 0xff;
    r[6] = (a->n[7] >> 18) & 0xff;
    r[7] = (a->n[7] >> 10) & 0xff;
    r[8] = (a->n[7] >> 2) & 0xff;
    r[9] = ((a->n[7] & 0x3) << 6) | ((a->n[6] >> 20) & 0x3f);
    r[10] = (a->n[6] >> 12) & 0xff;
    r[11] = (a->n[6] >> 4) & 0xff;
    r[12] = ((a->n[6] & 0xf) << 4) | ((a->n[5] >> 22) & 0xf);
    r[13] = (a->n[5] >> 14) & 0xff;
    r[14] = (a->n[5] >> 6) & 0xff;
    r[15] = ((a->n[5] & 0x3f) << 2) | ((a->n[4] >> 24) & 0x3);
    r[16] = (a->n[4] >> 16) & 0xff;
    r[17] = (a->n[4] >> 8) & 0xff;
    r[18] = a->n[4] & 0xff;
    r[19] = (a->n[3] >> 18) & 0xff;
    r[20] = (a->n[3] >> 10) & 0xff;
    r[21] = (a->n[3] >> 2) & 0xff;
    r[22] = ((a->n[3] & 0x3) << 6) | ((a->n[2] >> 20) & 0x3f);
    r[23] = (a->n[2] >> 12) & 0xff;
    r[24] = (a->n[2] >> 4) & 0xff;
    r[25] = ((a->n[2] & 0xf) << 4) | ((a->n[1] >> 22) & 0xf);
    r[26] = (a->n[1] >> 14) & 0xff;
    r[27] = (a->n[1] >> 6) & 0xff;
    r[28] = ((a->n[1] & 0x3f) << 2) | ((a->n[0] >> 24) & 0x3);
    r[29] = (a->n[0] >> 16) & 0xff;
    r[30] = (a->n[0] >> 8) & 0xff;
    r[31] = a->n[0] & 0xff;
}

SECP256K1_INLINE static void secp256k1_fe_negate(secp256k1_fe *r, const secp256k1_fe *a, int m) {
#ifdef VERIFY
    VERIFY_CHECK(a->magnitude <= m);
    secp256k1_fe_verify(a);
#endif
    r->n[0] = 0x3FFFC2FUL * 2 * (m + 1) - a->n[0];
    r->n[1] = 0x3FFFFBFUL * 2 * (m + 1) - a->n[1];
    r->n[2] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[2];
    r->n[3] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[3];
    r->n[4] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[4];
    r->n[5] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[5];
    r->n[6] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[6];
    r->n[7] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[7];
    r->n[8] = 0x3FFFFFFUL * 2 * (m + 1) - a->n[8];
    r->n[9] = 0x03FFFFFUL * 2 * (m + 1) - a->n[9];
#ifdef VERIFY
    r->magnitude = m + 1;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

SECP256K1_INLINE static void secp256k1_fe_mul_int(secp256k1_fe *r, int a) {
    r->n[0] *= a;
    r->n[1] *= a;
    r->n[2] *= a;
    r->n[3] *= a;
    r->n[4] *= a;
    r->n[5] *= a;
    r->n[6] *= a;
    r->n[7] *= a;
    r->n[8] *= a;
    r->n[9] *= a;
#ifdef VERIFY
    r->magnitude *= a;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

SECP256K1_INLINE static void secp256k1_fe_add(secp256k1_fe *r, const secp256k1_fe *a) {
#ifdef VERIFY
    secp256k1_fe_verify(a);
#endif
    r->n[0] += a->n[0];
    r->n[1] += a->n[1];
    r->n[2] += a->n[2];
    r->n[3] += a->n[3];
    r->n[4] += a->n[4];
    r->n[5] += a->n[5];
    r->n[6] += a->n[6];
    r->n[7] += a->n[7];
    r->n[8] += a->n[8];
    r->n[9] += a->n[9];
#ifdef VERIFY
    r->magnitude += a->magnitude;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

#if defined(USE_EXTERNAL_ASM)

/* External assembler implementation */
void secp256k1_fe_mul_inner(uint32_t *r, const uint32_t *a, const uint32_t * SECP256K1_RESTRICT b);
void secp256k1_fe_sqr_inner(uint32_t *r, const uint32_t *a);

#else

#ifdef VERIFY
#define VERIFY_BITS(x, n) VERIFY_CHECK(((x) >> (n)) == 0)
#else
#define VERIFY_BITS(x, n) do { } while(0)
#endif

SECP256K1_INLINE static void secp256k1_fe_mul_inner(uint32_t *r, const uint32_t *a, const uint32_t * SECP256K1_RESTRICT b) {

    const uint32_t M = 0x3FFFFFFUL, R0 = 0x3D10UL, R1 = 0x400UL;
    int32_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4],
            a5 = a[5], a6 = a[6], a7 = a[7], a8 = a[8], a9 = a[9];
    int32_t b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3], b4 = b[4],
            b5 = b[5], b6 = b[6], b7 = b[7], b8 = b[8], b9 = b[9];
    int64_t f0, f1, f2, f3, f4, f5, f6, f7, f8, f9, p18;
    uint32_t u0, u1, u2, u3, u4, u5, u6, u7, u8, u9;
    uint32_t t7, t8, t9, tx;
    uint64_t c, d;

    VERIFY_CHECK(r != b);
    VERIFY_CHECK(a != b);

    VERIFY_BITS(a[0], 30);
    VERIFY_BITS(a[1], 30);
    VERIFY_BITS(a[2], 30);
    VERIFY_BITS(a[3], 30);
    VERIFY_BITS(a[4], 30);
    VERIFY_BITS(a[5], 30);
    VERIFY_BITS(a[6], 30);
    VERIFY_BITS(a[7], 30);
    VERIFY_BITS(a[8], 30);
    VERIFY_BITS(a[9], 27);

    VERIFY_BITS(b[0], 30);
    VERIFY_BITS(b[1], 30);
    VERIFY_BITS(b[2], 30);
    VERIFY_BITS(b[3], 30);
    VERIFY_BITS(b[4], 30);
    VERIFY_BITS(b[5], 30);
    VERIFY_BITS(b[6], 30);
    VERIFY_BITS(b[7], 30);
    VERIFY_BITS(b[8], 30);
    VERIFY_BITS(b[9], 27);

    /** [... a b c] is a shorthand for ... + a<<52 + b<<26 + c<<0 mod n.
     *  for 0 <= x <= 9, px is a shorthand for sum(a[i]*b[x-i], i=0..x).
     *  for 9 <= x <= 18, px is a shorthand for sum(a[i]*b[x-i], i=(x-9)..9)
     *  Note that [x 0 0 0 0 0 0 0 0 0 0] = [x*R1 x*R0].
     */

    p18   = (int64_t)a9 * b9;

    f0    = (int64_t)a0 * b0;
    f1    = (int64_t)a1 * b1 + f0;
    f2    = (int64_t)a2 * b2 + f1;
    f3    = (int64_t)a3 * b3 + f2;
    f4    = (int64_t)a4 * b4 + f3;
    f5    = (int64_t)a5 * b5 + f4;
    f6    = (int64_t)a6 * b6 + f5;
    f7    = (int64_t)a7 * b7 + f6;
    f8    = (int64_t)a8 * b8 + f7;
    f9    = p18 + f8;

    d     = f7
          + (int64_t)(a7 - a0) * (b0 - b7)
          + (int64_t)(a6 - a1) * (b1 - b6)
          + (int64_t)(a5 - a2) * (b2 - b5)
          + (int64_t)(a4 - a3) * (b3 - b4);
    c     = f9 - f7
          + (int64_t)(a9 - a8) * (b8 - b9);

    VERIFY_BITS(c, 58);
    VERIFY_BITS(d, 63);

    u7    = (uint32_t)c & M; c >>= 26; d += (uint64_t)u7 * R0;
    t7    = (uint32_t)d & M; d >>= 26; d += (uint64_t)u7 * R1;

    VERIFY_BITS(c, 32);
    VERIFY_BITS(d, 39);
    VERIFY_BITS(t7, 26);

/* [ 0   c   0   0   0   0   0   0   0   0   0   d  t7   0   0   0   0   0   0   0 ] ==
 * [ 0   0 p17   0   0   0   0   0   0   0   0   0 p07   0   0   0   0   0   0   0 ] */

    d    += f8
          + (int64_t)(a8 - a0) * (b0 - b8)
          + (int64_t)(a7 - a1) * (b1 - b7)
          + (int64_t)(a6 - a2) * (b2 - b6)
          + (int64_t)(a5 - a3) * (b3 - b5);
    c    += p18;

    VERIFY_BITS(c, 55);
/*  VERIFY_BITS(d, 64); */
    VERIFY_CHECK(~d >= (uint64_t)R0 << 32);

    u8    = (uint32_t)c;     c >>= 32; d += (uint64_t)u8 * R0;
    t8    = (uint32_t)d & M; d >>= 26; d += (uint64_t)u8 * R1;

    VERIFY_BITS(c, 23);
    VERIFY_BITS(d, 43);
    VERIFY_BITS(t8, 26);

/* [ (c<<6)   0   0   0   0   0   0   0   0   0   d  t8  t7   0   0   0   0   0   0   0 ] ==
 * [      0 p18 p17   0   0   0   0   0   0   0   0 p08 p07   0   0   0   0   0   0   0 ] */

    d    += f9
          + (int64_t)(a9 - a0) * (b0 - b9)
          + (int64_t)(a8 - a1) * (b1 - b8)
          + (int64_t)(a7 - a2) * (b2 - b7)
          + (int64_t)(a6 - a3) * (b3 - b6)
          + (int64_t)(a5 - a4) * (b4 - b5);

/*  VERIFY_BITS(d, 64); */
    VERIFY_CHECK(~d >= (uint64_t)R0 << 29);

    u9    = (uint32_t)c;               d += (uint64_t)u9 * (R0 << 6);
    t9    = (uint32_t)d & M; d >>= 26; d += (uint64_t)u9 * (R1 << 6);

    VERIFY_BITS(d, 40);
    VERIFY_BITS(t9, 26);

/* [ 0   0   0   0   0   0   0   0   0   d  t9  t8  t7   0   0   0   0   0   0   0 ] ==
 * [ 0 p18 p17   0   0   0   0   0   0   0 p09 p08 p07   0   0   0   0   0   0   0 ] */

    tx    = t9 >> 22; t9 &= (M >> 4);

    VERIFY_BITS(t9, 22);
    VERIFY_BITS(tx, 4);

    c     = f0;
    d    += f9 - f0
          + (int64_t)(a9 - a1) * (b1 - b9)
          + (int64_t)(a8 - a2) * (b2 - b8)
          + (int64_t)(a7 - a3) * (b3 - b7)
          + (int64_t)(a6 - a4) * (b4 - b6);

    VERIFY_BITS(c, 60);
    VERIFY_BITS(d, 63);

    u0    = (uint32_t)d & M; d >>= 26;
    u0    = (u0 << 4) | tx;            c += (uint64_t)u0 * (R0 >> 4);
    r[0]  = (uint32_t)c & M; c >>= 26; c += (uint64_t)u0 * (R1 >> 4);

    VERIFY_BITS(c, 37);
    VERIFY_BITS(d, 37);
    VERIFY_BITS(r[0], 26);

/* [ 0   0   0   0   0   0   0   0   d   0  t9  t8  t7   0   0   0   0   0   c  r0 ] ==
 * [ 0 p18 p17   0   0   0   0   0   0 p10 p09 p08 p07   0   0   0   0   0   0 p00 ] */

    c    += f1
          + (int64_t)(a1 - a0) * (b0 - b1);
    d    += f9 - f1
          + (int64_t)(a9 - a2) * (b2 - b9)
          + (int64_t)(a8 - a3) * (b3 - b8)
          + (int64_t)(a7 - a4) * (b4 - b7)
          + (int64_t)(a6 - a5) * (b5 - b6);

    VERIFY_BITS(c, 62);
    VERIFY_BITS(d, 63);

    u1    = (uint32_t)d & M; d >>= 26; c += (uint64_t)u1 * R0;
    r[1]  = (uint32_t)c & M; c >>= 26; c += (uint64_t)u1 * R1;

    VERIFY_BITS(c, 37);
    VERIFY_BITS(d, 37);
    VERIFY_BITS(r[1], 26);

/* [ 0   0   0   0   0   0   0   d   0   0  t9  t8  t7   0   0   0   0   c r_1 r_0 ] ==
 * [ 0 p18 p17   0   0   0   0   0 p11 p10 p09 p08 p07   0   0   0   0   0 p01 p00 ] */

    c    += f2
          + (int64_t)(a2 - a0) * (b0 - b2);
    d    += f9 - f2
          + (int64_t)(a9 - a3) * (b3 - b9)
          + (int64_t)(a8 - a4) * (b4 - b8)
          + (int64_t)(a7 - a5) * (b5 - b7);

    VERIFY_BITS(c, 62);
    VERIFY_BITS(d, 63);

    u2    = (uint32_t)d & M; d >>= 26; c += (uint64_t)u2 * R0;
    r[2]  = (uint32_t)c & M; c >>= 26; c += (uint64_t)u2 * R1;

    VERIFY_BITS(c, 37);
    VERIFY_BITS(d, 37);
    VERIFY_BITS(r[2], 26);

/* [ 0   0   0   0   0   0   d   0   0   0  t9  t8  t7   0   0   0   c r_2 r_1 r_0 ] ==
 * [ 0 p18 p17   0   0   0   0 p12 p11 p10 p09 p08 p07   0   0   0   0 p02 p01 p00 ] */

    c    += f3
          + (int64_t)(a3 - a0) * (b0 - b3)
          + (int64_t)(a2 - a1) * (b1 - b2);
    d    += f9 - f3
          + (int64_t)(a9 - a4) * (b4 - b9)
          + (int64_t)(a8 - a5) * (b5 - b8)
          + (int64_t)(a7 - a6) * (b6 - b7);

    VERIFY_BITS(c, 63);
    VERIFY_BITS(d, 63);

    u3    = (uint32_t)d & M; d >>= 26; c += (uint64_t)u3 * R0;
    r[3]  = (uint32_t)c & M; c >>= 26; c += (uint64_t)u3 * R1;

    VERIFY_BITS(c, 38);
    VERIFY_BITS(d, 37);
    VERIFY_BITS(r[3], 26);

/* [ 0   0   0   0   0   d   0   0   0   0  t9  t8  t7   0   0   c r_3 r_2 r_1 r_0 ] ==
 * [ 0 p18 p17   0   0   0 p13 p12 p11 p10 p09 p08 p07   0   0   0 p03 p02 p01 p00 ] */

    c    += f4
          + (int64_t)(a4 - a0) * (b0 - b4)
          + (int64_t)(a3 - a1) * (b1 - b3);
    d    += f9 - f4
          + (int64_t)(a9 - a5) * (b5 - b9)
          + (int64_t)(a8 - a6) * (b6 - b8);

    VERIFY_BITS(c, 63);
    VERIFY_BITS(d, 62);

    u4    = (uint32_t)d & M; d >>= 26; c += (uint64_t)u4 * R0;
    r[4]  = (uint32_t)c & M; c >>= 26; c += (uint64_t)u4 * R1;

    VERIFY_BITS(c, 38);
    VERIFY_BITS(d, 36);
    VERIFY_BITS(r[4], 26);

/* [ 0   0   0   0   d   0   0   0   0   0  t9  t8  t7   0   c r_4 r_3 r_2 r_1 r_0 ] ==
 * [ 0 p18 p17   0   0 p14 p13 p12 p11 p10 p09 p08 p07   0   0 p04 p03 p02 p01 p00 ] */

    c    += f5
          + (int64_t)(a5 - a0) * (b0 - b5)
          + (int64_t)(a4 - a1) * (b1 - b4)
          + (int64_t)(a3 - a2) * (b2 - b3);
    d    += f9 - f5
          + (int64_t)(a9 - a6) * (b6 - b9)
          + (int64_t)(a8 - a7) * (b7 - b8);

    VERIFY_BITS(c, 63);
    VERIFY_BITS(d, 62);

    u5    = (uint32_t)d & M; d >>= 26; c += (uint64_t)u5 * R0;
    r[5]  = (uint32_t)c & M; c >>= 26; c += (uint64_t)u5 * R1;

    VERIFY_BITS(c, 38);
    VERIFY_BITS(d, 36);
    VERIFY_BITS(r[5], 26);

/* [ 0   0   0   d   0   0   0   0   0   0  t9  t8  t7   c r_5 r_4 r_3 r_2 r_1 r_0 ] ==
 * [ 0 p18 p17   0 p15 p14 p13 p12 p11 p10 p09 p08 p07   0 p05 p04 p03 p02 p01 p00 ] */

    c    += f6
          + (int64_t)(a6 - a0) * (b0 - b6)
          + (int64_t)(a5 - a1) * (b1 - b5)
          + (int64_t)(a4 - a2) * (b2 - b4);
    d    += f9 - f6
          + (int64_t)(a9 - a7) * (b7 - b9);

    VERIFY_BITS(c, 63);
    VERIFY_BITS(d, 61);

    u6    = (uint32_t)d;     d >>= 32; c += (uint64_t)u6 * R0;
    r[6]  = (uint32_t)c & M; c >>= 26; c += (uint64_t)u6 * R1;

    VERIFY_BITS(c, 43);
    VERIFY_BITS(d, 29);
    VERIFY_BITS(r[6], 26);

/* [ 0   0 (d<<6)   0   0   0   0   0   0   0  t9  t8 (c+t7) r_6 r_5 r_4 r_3 r_2 r_1 r_0 ] ==
 * [ 0 p18    p17 p16 p15 p14 p13 p12 p11 p10 p09 p08    p07 p06 p05 p04 p03 p02 p01 p00 ] */

    c    += t7;
    u7    = (uint32_t)d;               c += (uint64_t)u7 * (R0 << 6);
    r[7]  = (uint32_t)c & M; c >>= 26; c += (uint64_t)u7 * (R1 << 6);

    VERIFY_BITS(c, 46);
    VERIFY_BITS(r[7], 26);

/* [ 0   0   0   0   0   0   0   0   0   0  t9 (c+t8) r_7 r_6 r_5 r_4 r_3 r_2 r_1 r_0 ] ==
 * [ 0 p18 p17 p16 p15 p14 p13 p12 p11 p10 p09    p08 p07 p06 p05 p04 p03 p02 p01 p00 ] */

    c    += t8;
    r[8]  = (uint32_t)c & M; c >>= 26;

    VERIFY_BITS(c, 20);
    VERIFY_BITS(r[8], 26);

/* [ 0   0   0   0   0   0   0   0   0   0 (c+t9) r_8 r_7 r_6 r_5 r_4 r_3 r_2 r_1 r_0 ] ==
 * [ 0 p18 p17 p16 p15 p14 p13 p12 p11 p10    p09 p08 p07 p06 p05 p04 p03 p02 p01 p00 ] */

    r[9]  = t9 + (uint32_t)c;

    VERIFY_BITS(r[9], 23);

/* [ 0   0   0   0   0   0   0   0   0   0 r_9 r_8 r_7 r_6 r_5 r_4 r_3 r_2 r_1 r_0 ] ==
 * [ 0 p18 p17 p16 p15 p14 p13 p12 p11 p10 p09 p08 p07 p06 p05 p04 p03 p02 p01 p00 ] */
}

SECP256K1_INLINE static void secp256k1_fe_sqr_inner(uint32_t *r, const uint32_t *a) {

    const uint32_t M = 0x3FFFFFFUL, R0 = 0x3D10UL, R1 = 0x400UL;
    uint32_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4],
             a5 = a[5], a6 = a[6], a7 = a[7], a8 = a[8], a9 = a[9];
    uint32_t u0, u1, u2, u3, u4, u5, u6, u7, u8, u9;
    uint32_t t7, t8, t9, tx;
    uint64_t c, d;

    VERIFY_BITS(a[0], 30);
    VERIFY_BITS(a[1], 30);
    VERIFY_BITS(a[2], 30);
    VERIFY_BITS(a[3], 30);
    VERIFY_BITS(a[4], 30);
    VERIFY_BITS(a[5], 30);
    VERIFY_BITS(a[6], 30);
    VERIFY_BITS(a[7], 30);
    VERIFY_BITS(a[8], 30);
    VERIFY_BITS(a[9], 27);

    /** [... a b c] is a shorthand for ... + a<<52 + b<<26 + c<<0 mod n.
     *  for 0 <= x <= 9, px is a shorthand for sum(a[i]*b[x-i], i=0..x).
     *  for 9 <= x <= 18, px is a shorthand for sum(a[i]*b[x-i], i=(x-9)..9)
     *  Note that [x 0 0 0 0 0 0 0 0 0 0] = [x*R1 x*R0].
     */

    d     = (uint64_t)a0 * (a7*2)
          + (uint64_t)a1 * (a6*2)
          + (uint64_t)a2 * (a5*2)
          + (uint64_t)a3 * (a4*2);
    c     = (uint64_t)a8 * (a9*2);

    VERIFY_BITS(c, 58);
    VERIFY_BITS(d, 63);

    u7    = (uint32_t)c & M; c >>= 26; d += (uint64_t)u7 * R0;
    t7    = (uint32_t)d & M; d >>= 26; d += (uint64_t)u7 * R1;

    VERIFY_BITS(c, 32);
    VERIFY_BITS(d, 39);
    VERIFY_BITS(t7, 26);

/* [ 0   c   0   0   0   0   0   0   0   0   0   d  t7   0   0   0   0   0   0   0 ] ==
 * [ 0   0 p17   0   0   0   0   0   0   0   0   0 p07   0   0   0   0   0   0   0 ] */

    d    += (uint64_t)a0 * (a8*2)
          + (uint64_t)a1 * (a7*2)
          + (uint64_t)a2 * (a6*2)
          + (uint64_t)a3 * (a5*2)
          + (uint64_t)a4 * a4;
    c    += (uint64_t)a9 * a9;

    VERIFY_BITS(c, 55);
/*  VERIFY_BITS(d, 64); */
    VERIFY_CHECK(~d >= (uint64_t)R0 << 32);

    u8    = (uint32_t)c;     c >>= 32; d += (uint64_t)u8 * R0;
    t8    = (uint32_t)d & M; d >>= 26; d += (uint64_t)u8 * R1;

    VERIFY_BITS(c, 23);
    VERIFY_BITS(d, 43);
    VERIFY_BITS(t8, 26);

/* [ (c<<6)   0   0   0   0   0   0   0   0   0   d  t8  t7   0   0   0   0   0   0   0 ] ==
 * [      0 p18 p17   0   0   0   0   0   0   0   0 p08 p07   0   0   0   0   0   0   0 ] */

    d    += (uint64_t)a0 * (a9*2)
          + (uint64_t)a1 * (a8*2)
          + (uint64_t)a2 * (a7*2)
          + (uint64_t)a3 * (a6*2)
          + (uint64_t)a4 * (a5*2);

/*  VERIFY_BITS(d, 64); */
    VERIFY_CHECK(~d >= (uint64_t)R0 << 29);

    u9    = (uint32_t)c;               d += (uint64_t)u9 * (R0 << 6);
    t9    = (uint32_t)d & M; d >>= 26; d += (uint64_t)u9 * (R1 << 6);

    VERIFY_BITS(d, 40);
    VERIFY_BITS(t9, 26);

/* [ 0   0   0   0   0   0   0   0   0   d  t9  t8  t7   0   0   0   0   0   0   0 ] ==
 * [ 0 p18 p17   0   0   0   0   0   0   0 p09 p08 p07   0   0   0   0   0   0   0 ] */

    tx    = t9 >> 22; t9 &= (M >> 4);

    VERIFY_BITS(t9, 22);
    VERIFY_BITS(tx, 4);

    c     = (uint64_t)a0 * a0;
    d    += (uint64_t)a1 * (a9*2)
          + (uint64_t)a2 * (a8*2)
          + (uint64_t)a3 * (a7*2)
          + (uint64_t)a4 * (a6*2)
          + (uint64_t)a5 * a5;

    VERIFY_BITS(c, 60);
    VERIFY_BITS(d, 63);

    u0    = (uint32_t)d & M; d >>= 26;
    u0    = (u0 << 4) | tx;            c += (uint64_t)u0 * (R0 >> 4);
    r[0]  = (uint32_t)c & M; c >>= 26; c += (uint64_t)u0 * (R1 >> 4);

    VERIFY_BITS(c, 37);
    VERIFY_BITS(d, 37);
    VERIFY_BITS(r[0], 26);

/* [ 0   0   0   0   0   0   0   0   d   0  t9  t8  t7   0   0   0   0   0   c  r0 ] ==
 * [ 0 p18 p17   0   0   0   0   0   0 p10 p09 p08 p07   0   0   0   0   0   0 p00 ] */

    c    += (uint64_t)a0 * (a1*2);
    d    += (uint64_t)a2 * (a9*2)
          + (uint64_t)a3 * (a8*2)
          + (uint64_t)a4 * (a7*2)
          + (uint64_t)a5 * (a6*2);

    VERIFY_BITS(c, 62);
    VERIFY_BITS(d, 63);

    u1    = (uint32_t)d & M; d >>= 26; c += (uint64_t)u1 * R0;
    r[1]  = (uint32_t)c & M; c >>= 26; c += (uint64_t)u1 * R1;

    VERIFY_BITS(c, 37);
    VERIFY_BITS(d, 37);
    VERIFY_BITS(r[1], 26);

/* [ 0   0   0   0   0   0   0   d   0   0  t9  t8  t7   0   0   0   0   c r_1 r_0 ] ==
 * [ 0 p18 p17   0   0   0   0   0 p11 p10 p09 p08 p07   0   0   0   0   0 p01 p00 ] */

    c    += (uint64_t)a0 * (a2*2)
          + (uint64_t)a1 * a1;
    d    += (uint64_t)a3 * (a9*2)
          + (uint64_t)a4 * (a8*2)
          + (uint64_t)a5 * (a7*2)
          + (uint64_t)a6 * a6;

    VERIFY_BITS(c, 62);
    VERIFY_BITS(d, 63);

    u2    = (uint32_t)d & M; d >>= 26; c += (uint64_t)u2 * R0;
    r[2]  = (uint32_t)c & M; c >>= 26; c += (uint64_t)u2 * R1;

    VERIFY_BITS(c, 37);
    VERIFY_BITS(d, 37);
    VERIFY_BITS(r[2], 26);

/* [ 0   0   0   0   0   0   d   0   0   0  t9  t8  t7   0   0   0   c r_2 r_1 r_0 ] ==
 * [ 0 p18 p17   0   0   0   0 p12 p11 p10 p09 p08 p07   0   0   0   0 p02 p01 p00 ] */

    c    += (uint64_t)a0 * (a3*2)
          + (uint64_t)a1 * (a2*2);
    d    += (uint64_t)a4 * (a9*2)
          + (uint64_t)a5 * (a8*2)
          + (uint64_t)a6 * (a7*2);

    VERIFY_BITS(c, 63);
    VERIFY_BITS(d, 63);

    u3    = (uint32_t)d & M; d >>= 26; c += (uint64_t)u3 * R0;
    r[3]  = (uint32_t)c & M; c >>= 26; c += (uint64_t)u3 * R1;

    VERIFY_BITS(c, 38);
    VERIFY_BITS(d, 37);
    VERIFY_BITS(r[3], 26);

/* [ 0   0   0   0   0   d   0   0   0   0  t9  t8  t7   0   0   c r_3 r_2 r_1 r_0 ] ==
 * [ 0 p18 p17   0   0   0 p13 p12 p11 p10 p09 p08 p07   0   0   0 p03 p02 p01 p00 ] */

    c    += (uint64_t)a0 * (a4*2)
          + (uint64_t)a1 * (a3*2)
          + (uint64_t)a2 * a2;
    d    += (uint64_t)a5 * (a9*2)
          + (uint64_t)a6 * (a8*2)
          + (uint64_t)a7 * a7;

    VERIFY_BITS(c, 63);
    VERIFY_BITS(d, 62);

    u4    = (uint32_t)d & M; d >>= 26; c += (uint64_t)u4 * R0;
    r[4]  = (uint32_t)c & M; c >>= 26; c += (uint64_t)u4 * R1;

    VERIFY_BITS(c, 38);
    VERIFY_BITS(d, 36);
    VERIFY_BITS(r[4], 26);

/* [ 0   0   0   0   d   0   0   0   0   0  t9  t8  t7   0   c r_4 r_3 r_2 r_1 r_0 ] ==
 * [ 0 p18 p17   0   0 p14 p13 p12 p11 p10 p09 p08 p07   0   0 p04 p03 p02 p01 p00 ] */

    c    += (uint64_t)a0 * (a5*2)
          + (uint64_t)a1 * (a4*2)
          + (uint64_t)a2 * (a3*2);
    d    += (uint64_t)a6 * (a9*2)
          + (uint64_t)a7 * (a8*2);

    VERIFY_BITS(c, 63);
    VERIFY_BITS(d, 62);

    u5    = (uint32_t)d & M; d >>= 26; c += (uint64_t)u5 * R0;
    r[5]  = (uint32_t)c & M; c >>= 26; c += (uint64_t)u5 * R1;

    VERIFY_BITS(c, 38);
    VERIFY_BITS(d, 36);
    VERIFY_BITS(r[5], 26);

/* [ 0   0   0   d   0   0   0   0   0   0  t9  t8  t7   c r_5 r_4 r_3 r_2 r_1 r_0 ] ==
 * [ 0 p18 p17   0 p15 p14 p13 p12 p11 p10 p09 p08 p07   0 p05 p04 p03 p02 p01 p00 ] */

    c    += (uint64_t)a0 * (a6*2)
          + (uint64_t)a1 * (a5*2)
          + (uint64_t)a2 * (a4*2)
          + (uint64_t)a3 * a3;
    d    += (uint64_t)a7 * (a9*2)
          + (uint64_t)a8 * a8;

    VERIFY_BITS(c, 63);
    VERIFY_BITS(d, 61);

    u6    = (uint32_t)d;     d >>= 32; c += (uint64_t)u6 * R0;
    r[6]  = (uint32_t)c & M; c >>= 26; c += (uint64_t)u6 * R1;

    VERIFY_BITS(c, 43);
    VERIFY_BITS(d, 29);
    VERIFY_BITS(r[6], 26);

/* [ 0   0 (d<<6)   0   0   0   0   0   0   0  t9  t8 (c+t7) r_6 r_5 r_4 r_3 r_2 r_1 r_0 ] ==
 * [ 0 p18    p17 p16 p15 p14 p13 p12 p11 p10 p09 p08    p07 p06 p05 p04 p03 p02 p01 p00 ] */

    c    += t7;
    u7    = (uint32_t)d;               c += (uint64_t)u7 * (R0 << 6);
    r[7]  = (uint32_t)c & M; c >>= 26; c += (uint64_t)u7 * (R1 << 6);

    VERIFY_BITS(c, 46);
    VERIFY_BITS(r[7], 26);

/* [ 0   0   0   0   0   0   0   0   0   0  t9 (c+t8) r_7 r_6 r_5 r_4 r_3 r_2 r_1 r_0 ] ==
 * [ 0 p18 p17 p16 p15 p14 p13 p12 p11 p10 p09    p08 p07 p06 p05 p04 p03 p02 p01 p00 ] */

    c    += t8;
    r[8]  = (uint32_t)c & M; c >>= 26;

    VERIFY_BITS(c, 20);
    VERIFY_BITS(r[8], 26);

/* [ 0   0   0   0   0   0   0   0   0   0 (c+t9) r_8 r_7 r_6 r_5 r_4 r_3 r_2 r_1 r_0 ] ==
 * [ 0 p18 p17 p16 p15 p14 p13 p12 p11 p10    p09 p08 p07 p06 p05 p04 p03 p02 p01 p00 ] */

    r[9]  = t9 + (uint32_t)c;

    VERIFY_BITS(r[9], 23);

/* [ 0   0   0   0   0   0   0   0   0   0 r_9 r_8 r_7 r_6 r_5 r_4 r_3 r_2 r_1 r_0 ] ==
 * [ 0 p18 p17 p16 p15 p14 p13 p12 p11 p10 p09 p08 p07 p06 p05 p04 p03 p02 p01 p00 ] */
}
#endif

static void secp256k1_fe_mul(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe * SECP256K1_RESTRICT b) {
#ifdef VERIFY
    VERIFY_CHECK(a->magnitude <= 8);
    VERIFY_CHECK(b->magnitude <= 8);
    secp256k1_fe_verify(a);
    secp256k1_fe_verify(b);
    VERIFY_CHECK(r != b);
    VERIFY_CHECK(a != b);
#endif
    secp256k1_fe_mul_inner(r->n, a->n, b->n);
#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_sqr(secp256k1_fe *r, const secp256k1_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->magnitude <= 8);
    secp256k1_fe_verify(a);
#endif
    secp256k1_fe_sqr_inner(r->n, a->n);
#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

static SECP256K1_INLINE void secp256k1_fe_cmov(secp256k1_fe *r, const secp256k1_fe *a, int flag) {
    uint32_t mask0, mask1;
    VG_CHECK_VERIFY(r->n, sizeof(r->n));
    mask0 = flag + ~((uint32_t)0);
    mask1 = ~mask0;
    r->n[0] = (r->n[0] & mask0) | (a->n[0] & mask1);
    r->n[1] = (r->n[1] & mask0) | (a->n[1] & mask1);
    r->n[2] = (r->n[2] & mask0) | (a->n[2] & mask1);
    r->n[3] = (r->n[3] & mask0) | (a->n[3] & mask1);
    r->n[4] = (r->n[4] & mask0) | (a->n[4] & mask1);
    r->n[5] = (r->n[5] & mask0) | (a->n[5] & mask1);
    r->n[6] = (r->n[6] & mask0) | (a->n[6] & mask1);
    r->n[7] = (r->n[7] & mask0) | (a->n[7] & mask1);
    r->n[8] = (r->n[8] & mask0) | (a->n[8] & mask1);
    r->n[9] = (r->n[9] & mask0) | (a->n[9] & mask1);
#ifdef VERIFY
    if (flag) {
        r->magnitude = a->magnitude;
        r->normalized = a->normalized;
    }
#endif
}

static SECP256K1_INLINE void secp256k1_fe_storage_cmov(secp256k1_fe_storage *r, const secp256k1_fe_storage *a, int flag) {
    uint32_t mask0, mask1;
    VG_CHECK_VERIFY(r->n, sizeof(r->n));
    mask0 = flag + ~((uint32_t)0);
    mask1 = ~mask0;
    r->n[0] = (r->n[0] & mask0) | (a->n[0] & mask1);
    r->n[1] = (r->n[1] & mask0) | (a->n[1] & mask1);
    r->n[2] = (r->n[2] & mask0) | (a->n[2] & mask1);
    r->n[3] = (r->n[3] & mask0) | (a->n[3] & mask1);
    r->n[4] = (r->n[4] & mask0) | (a->n[4] & mask1);
    r->n[5] = (r->n[5] & mask0) | (a->n[5] & mask1);
    r->n[6] = (r->n[6] & mask0) | (a->n[6] & mask1);
    r->n[7] = (r->n[7] & mask0) | (a->n[7] & mask1);
}

static void secp256k1_fe_to_storage(secp256k1_fe_storage *r, const secp256k1_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
#endif
    r->n[0] = a->n[0] | a->n[1] << 26;
    r->n[1] = a->n[1] >> 6 | a->n[2] << 20;
    r->n[2] = a->n[2] >> 12 | a->n[3] << 14;
    r->n[3] = a->n[3] >> 18 | a->n[4] << 8;
    r->n[4] = a->n[4] >> 24 | a->n[5] << 2 | a->n[6] << 28;
    r->n[5] = a->n[6] >> 4 | a->n[7] << 22;
    r->n[6] = a->n[7] >> 10 | a->n[8] << 16;
    r->n[7] = a->n[8] >> 16 | a->n[9] << 10;
}

static SECP256K1_INLINE void secp256k1_fe_from_storage(secp256k1_fe *r, const secp256k1_fe_storage *a) {
    r->n[0] = a->n[0] & 0x3FFFFFFUL;
    r->n[1] = a->n[0] >> 26 | ((a->n[1] << 6) & 0x3FFFFFFUL);
    r->n[2] = a->n[1] >> 20 | ((a->n[2] << 12) & 0x3FFFFFFUL);
    r->n[3] = a->n[2] >> 14 | ((a->n[3] << 18) & 0x3FFFFFFUL);
    r->n[4] = a->n[3] >> 8 | ((a->n[4] << 24) & 0x3FFFFFFUL);
    r->n[5] = (a->n[4] >> 2) & 0x3FFFFFFUL;
    r->n[6] = a->n[4] >> 28 | ((a->n[5] << 4) & 0x3FFFFFFUL);
    r->n[7] = a->n[5] >> 22 | ((a->n[6] << 10) & 0x3FFFFFFUL);
    r->n[8] = a->n[6] >> 16 | ((a->n[7] << 16) & 0x3FFFFFFUL);
    r->n[9] = a->n[7] >> 10;
#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
#endif
}

static void secp256k1_fe_from_signed30(secp256k1_fe *r, const secp256k1_modinv32_signed30 *a) {
    const uint32_t M26 = UINT32_MAX >> 6;
    const uint32_t a0 = a->v[0], a1 = a->v[1], a2 = a->v[2], a3 = a->v[3], a4 = a->v[4],
                   a5 = a->v[5], a6 = a->v[6], a7 = a->v[7], a8 = a->v[8];

    /* The output from secp256k1_modinv32{_var} should be normalized to range [0,modulus), and
     * have limbs in [0,2^30). The modulus is < 2^256, so the top limb must be below 2^(256-30*8).
     */
    VERIFY_CHECK(a0 >> 30 == 0);
    VERIFY_CHECK(a1 >> 30 == 0);
    VERIFY_CHECK(a2 >> 30 == 0);
    VERIFY_CHECK(a3 >> 30 == 0);
    VERIFY_CHECK(a4 >> 30 == 0);
    VERIFY_CHECK(a5 >> 30 == 0);
    VERIFY_CHECK(a6 >> 30 == 0);
    VERIFY_CHECK(a7 >> 30 == 0);
    VERIFY_CHECK(a8 >> 16 == 0);

    r->n[0] =  a0                   & M26;
    r->n[1] = (a0 >> 26 | a1 <<  4) & M26;
    r->n[2] = (a1 >> 22 | a2 <<  8) & M26;
    r->n[3] = (a2 >> 18 | a3 << 12) & M26;
    r->n[4] = (a3 >> 14 | a4 << 16) & M26;
    r->n[5] = (a4 >> 10 | a5 << 20) & M26;
    r->n[6] = (a5 >>  6 | a6 << 24) & M26;
    r->n[7] = (a6 >>  2           ) & M26;
    r->n[8] = (a6 >> 28 | a7 <<  2) & M26;
    r->n[9] = (a7 >> 24 | a8 <<  6);

#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_to_signed30(secp256k1_modinv32_signed30 *r, const secp256k1_fe *a) {
    const uint32_t M30 = UINT32_MAX >> 2;
    const uint64_t a0 = a->n[0], a1 = a->n[1], a2 = a->n[2], a3 = a->n[3], a4 = a->n[4],
                   a5 = a->n[5], a6 = a->n[6], a7 = a->n[7], a8 = a->n[8], a9 = a->n[9];

#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
#endif

    r->v[0] = (a0       | a1 << 26) & M30;
    r->v[1] = (a1 >>  4 | a2 << 22) & M30;
    r->v[2] = (a2 >>  8 | a3 << 18) & M30;
    r->v[3] = (a3 >> 12 | a4 << 14) & M30;
    r->v[4] = (a4 >> 16 | a5 << 10) & M30;
    r->v[5] = (a5 >> 20 | a6 <<  6) & M30;
    r->v[6] = (a6 >> 24 | a7 <<  2
                        | a8 << 28) & M30;
    r->v[7] = (a8 >>  2 | a9 << 24) & M30;
    r->v[8] =  a9 >>  6;
}

static const secp256k1_modinv32_modinfo secp256k1_const_modinfo_fe = {
    {{-0x3D1, -4, 0, 0, 0, 0, 0, 0, 65536}},
    0x2DDACACFL
};

static void secp256k1_fe_inv(secp256k1_fe *r, const secp256k1_fe *x) {
    secp256k1_fe tmp;
    secp256k1_modinv32_signed30 s;

    tmp = *x;
    secp256k1_fe_normalize(&tmp);
    secp256k1_fe_to_signed30(&s, &tmp);
    secp256k1_modinv32(&s, &secp256k1_const_modinfo_fe);
    secp256k1_fe_from_signed30(r, &s);

    VERIFY_CHECK(secp256k1_fe_normalizes_to_zero(r) == secp256k1_fe_normalizes_to_zero(&tmp));
}

static void secp256k1_fe_inv_var(secp256k1_fe *r, const secp256k1_fe *x) {
    secp256k1_fe tmp;
    secp256k1_modinv32_signed30 s;

    tmp = *x;
    secp256k1_fe_normalize_var(&tmp);
    secp256k1_fe_to_signed30(&s, &tmp);
    secp256k1_modinv32_var(&s, &secp256k1_const_modinfo_fe);
    secp256k1_fe_from_signed30(r, &s);

    VERIFY_CHECK(secp256k1_fe_normalizes_to_zero(r) == secp256k1_fe_normalizes_to_zero(&tmp));
}

#endif /* SECP256K1_FIELD_REPR_IMPL_H */
