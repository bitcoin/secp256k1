/**********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_RECOVERY_MAIN_H
#define SECP256K1_MODULE_RECOVERY_MAIN_H

#include "include/secp256k1_recovery.h"

static void secp256k1_ecdsa_recoverable_signature_load(const secp256k1_context* ctx, secp256k1_scalar* r, secp256k1_scalar* s, int* recid, const secp256k1_ecdsa_recoverable_signature* sig) {
    (void)ctx;
    if (sizeof(secp256k1_scalar) == 32) {
        /* When the secp256k1_scalar type is exactly 32 byte, use its
         * representation inside secp256k1_ecdsa_signature, as conversion is very fast.
         * Note that secp256k1_ecdsa_signature_save must use the same representation. */
        memcpy(r, &sig->data[0], 32);
        memcpy(s, &sig->data[32], 32);
    } else {
        secp256k1_scalar_set_b32(r, &sig->data[0], NULL);
        secp256k1_scalar_set_b32(s, &sig->data[32], NULL);
    }
    *recid = sig->data[64];
}

static void secp256k1_ecdsa_recoverable_signature_save(secp256k1_ecdsa_recoverable_signature* sig, const secp256k1_scalar* r, const secp256k1_scalar* s, int recid) {
    if (sizeof(secp256k1_scalar) == 32) {
        memcpy(&sig->data[0], r, 32);
        memcpy(&sig->data[32], s, 32);
    } else {
        secp256k1_scalar_get_b32(&sig->data[0], r);
        secp256k1_scalar_get_b32(&sig->data[32], s);
    }
    sig->data[64] = recid;
}

int secp256k1_ecdsa_recoverable_signature_parse_compact(const secp256k1_context* ctx, secp256k1_ecdsa_recoverable_signature* sig, const unsigned char *input64, int recid) {
    secp256k1_scalar r, s;
    int ret = 1;
    int overflow = 0;

    (void)ctx;
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input64 != NULL);
    ARG_CHECK(recid >= 0 && recid <= 3);

    secp256k1_scalar_set_b32(&r, &input64[0], &overflow);
    ret &= !overflow;
    secp256k1_scalar_set_b32(&s, &input64[32], &overflow);
    ret &= !overflow;
    if (ret) {
        secp256k1_ecdsa_recoverable_signature_save(sig, &r, &s, recid);
    } else {
        memset(sig, 0, sizeof(*sig));
    }
    return ret;
}

int secp256k1_ecdsa_recoverable_signature_serialize_compact(const secp256k1_context* ctx, unsigned char *output64, int *recid, const secp256k1_ecdsa_recoverable_signature* sig) {
    secp256k1_scalar r, s;

    (void)ctx;
    ARG_CHECK(output64 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(recid != NULL);

    secp256k1_ecdsa_recoverable_signature_load(ctx, &r, &s, recid, sig);
    secp256k1_scalar_get_b32(&output64[0], &r);
    secp256k1_scalar_get_b32(&output64[32], &s);
    return 1;
}

int secp256k1_ecdsa_recoverable_signature_convert(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const secp256k1_ecdsa_recoverable_signature* sigin) {
    secp256k1_scalar r, s;
    int recid;

    (void)ctx;
    ARG_CHECK(sig != NULL);
    ARG_CHECK(sigin != NULL);

    secp256k1_ecdsa_recoverable_signature_load(ctx, &r, &s, &recid, sigin);
    secp256k1_ecdsa_signature_save(sig, &r, &s);
    return 1;
}

static int secp256k1_ecdsa_sig_recover(const secp256k1_ecmult_context *ctx, const secp256k1_scalar *sigr, const secp256k1_scalar* sigs, secp256k1_ge *pubkey, const secp256k1_scalar *message, int recid) {
    unsigned char brx[32];
    secp256k1_fe fx;
    secp256k1_ge x;
    secp256k1_gej xj;
    secp256k1_scalar rn, u1, u2;
    secp256k1_gej qj;
    int r;

    if (secp256k1_scalar_is_zero(sigr) || secp256k1_scalar_is_zero(sigs)) {
        return 0;
    }

    secp256k1_scalar_get_b32(brx, sigr);
    r = secp256k1_fe_set_b32(&fx, brx);
    (void)r;
    VERIFY_CHECK(r); /* brx comes from a scalar, so is less than the order; certainly less than p */
    if (recid & 2) {
        if (secp256k1_fe_cmp_var(&fx, &secp256k1_ecdsa_const_p_minus_order) >= 0) {
            return 0;
        }
        secp256k1_fe_add(&fx, &secp256k1_ecdsa_const_order_as_fe);
    }
    if (!secp256k1_ge_set_xo_var(&x, &fx, recid & 1)) {
        return 0;
    }
    secp256k1_gej_set_ge(&xj, &x);
    secp256k1_scalar_inverse_var(&rn, sigr);
    secp256k1_scalar_mul(&u1, &rn, message);
    secp256k1_scalar_negate(&u1, &u1);
    secp256k1_scalar_mul(&u2, &rn, sigs);
    secp256k1_ecmult(ctx, &qj, &xj, &u2, &u1);
    secp256k1_ge_set_gej_var(pubkey, &qj);
    return !secp256k1_gej_is_infinity(&qj);
}

static int secp256k1_ecdsa_sig_recover_four(const secp256k1_ecmult_context *ctx, secp256k1_gej out[], size_t *n, const secp256k1_scalar *sigr, const secp256k1_scalar *rn, const secp256k1_scalar* sigs, const secp256k1_scalar *message) {
  unsigned char brx[32];
  secp256k1_fe rx, rx2;
  secp256k1_ge gex;
  secp256k1_gej xj1, xj1n, xj2, xj2n, u1j;
  secp256k1_scalar u1, u2, zero;
  int r;
  *n = 0;
  if (secp256k1_scalar_is_zero(sigr) || secp256k1_scalar_is_zero(sigs)) {
    return 0;
  }

  secp256k1_scalar_set_int(&zero, 0);
  secp256k1_gej_set_infinity(&u1j);
  secp256k1_scalar_get_b32(brx, sigr);
  r = secp256k1_fe_set_b32(&rx, brx);
  (void)r;
  VERIFY_CHECK(r); /* brx comes from a scalar, so is less than the order; certainly less than p */

  secp256k1_scalar_mul(&u1, rn, message);
  secp256k1_scalar_negate(&u1, &u1);
  secp256k1_scalar_mul(&u2, rn, sigs);
  secp256k1_ecmult(ctx, &u1j, &u1j, &zero, &u1);

  if (secp256k1_fe_cmp_var(&rx, &secp256k1_ecdsa_const_p_minus_order) < 0) {
    secp256k1_fe_copy_add(&rx2, &rx, &secp256k1_ecdsa_const_order_as_fe);
    if(secp256k1_ge_set_xquad(&gex, &rx2)) {
      secp256k1_gej_set_ge(&xj2, &gex);

      secp256k1_ecmult(ctx, &xj2, &xj2, &u2, NULL);

      secp256k1_gej_add_neg_var(&xj2, &xj2n, &u1j, &xj2, NULL);

      if (!secp256k1_gej_is_infinity(&xj2)) {
        memcpy(&out[*n], &xj2n, sizeof(out[*n]));
        (*n)++;
      }
      if (!secp256k1_gej_is_infinity(&xj2n)) {
        memcpy(&out[*n], &xj2n, sizeof(out[*n]));
        (*n)++;
      }
    }
  }

  if (secp256k1_ge_set_xquad(&gex, &rx)) {
    secp256k1_gej_set_ge(&xj1, &gex);
    secp256k1_ecmult(ctx, &xj1, &xj1, &u2, NULL);

    secp256k1_gej_add_neg_var(&xj1, &xj1n, &u1j, &xj1, NULL);

    if (!secp256k1_gej_is_infinity(&xj1)) {
      memcpy(&out[*n], &xj1, sizeof(out[*n]));
      (*n)++;
    }
    if (!secp256k1_gej_is_infinity(&xj1n)) {
      memcpy(&out[*n], &xj1n, sizeof(out[*n]));
      (*n)++;
    }
  }

  return *n > 0;
}

int secp256k1_ecdsa_sign_recoverable(const secp256k1_context* ctx, secp256k1_ecdsa_recoverable_signature *signature, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void* noncedata) {
    secp256k1_scalar r, s;
    secp256k1_scalar sec, non, msg;
    int recid;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(seckey != NULL);
    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_default;
    }

    secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    /* Fail if the secret key is invalid. */
    if (!overflow && !secp256k1_scalar_is_zero(&sec)) {
        unsigned char nonce32[32];
        unsigned int count = 0;
        secp256k1_scalar_set_b32(&msg, msg32, NULL);
        while (1) {
            ret = noncefp(nonce32, msg32, seckey, NULL, (void*)noncedata, count);
            if (!ret) {
                break;
            }
            secp256k1_scalar_set_b32(&non, nonce32, &overflow);
            if (!overflow && !secp256k1_scalar_is_zero(&non)) {
                if (secp256k1_ecdsa_sig_sign(&ctx->ecmult_gen_ctx, &r, &s, &sec, &msg, &non, &recid)) {
                    break;
                }
            }
            count++;
        }
        memset(nonce32, 0, 32);
        secp256k1_scalar_clear(&msg);
        secp256k1_scalar_clear(&non);
        secp256k1_scalar_clear(&sec);
    }
    if (ret) {
        secp256k1_ecdsa_recoverable_signature_save(signature, &r, &s, recid);
    } else {
        memset(signature, 0, sizeof(*signature));
    }
    return ret;
}

int secp256k1_ecdsa_recover(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const secp256k1_ecdsa_recoverable_signature *signature, const unsigned char *msg32) {
    secp256k1_ge q;
    secp256k1_scalar r, s;
    secp256k1_scalar m;
    int recid;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(pubkey != NULL);

    secp256k1_ecdsa_recoverable_signature_load(ctx, &r, &s, &recid, signature);
    VERIFY_CHECK(recid >= 0 && recid < 4);  /* should have been caught in parse_compact */
    secp256k1_scalar_set_b32(&m, msg32, NULL);
    if (secp256k1_ecdsa_sig_recover(&ctx->ecmult_ctx, &r, &s, &q, &m, recid)) {
        secp256k1_pubkey_save(pubkey, &q);
        return 1;
    } else {
        memset(pubkey, 0, sizeof(*pubkey));
        return 0;
    }
}


int secp256k1_ecdsa_recover_batch(const secp256k1_context* ctx, secp256k1_scratch_space *scratch, const secp256k1_pubkey *pubkeys_out[], const secp256k1_ecdsa_signature *const sigs[], const unsigned char *const msgs32[], size_t n, const secp256k1_pubkey *const pubkeys[], size_t pubkeys_n) {
  secp256k1_scalar m;
  secp256k1_scalar *ss, *rs, *rns;
  secp256k1_ge *ges;
  secp256k1_gej four_gejs[4];
  size_t i, j, k, l, n_keys;
  size_t scratch_checkpoint;

  VERIFY_CHECK(ctx != NULL);
  ARG_CHECK(scratch != NULL);
  ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
  if (n > 0) {
    ARG_CHECK(msgs32 != NULL);
    ARG_CHECK(sigs != NULL);
    ARG_CHECK(pubkeys != NULL);
  }
  memset(pubkeys_out, 0, sizeof(*pubkeys_out)*n*4); /* TODO: Should replace with a loop that writes NULLs */
  scratch_checkpoint = secp256k1_scratch_checkpoint(&ctx->error_callback, scratch);

  ges = (secp256k1_ge *) secp256k1_scratch_alloc(&ctx->error_callback, scratch, pubkeys_n * sizeof(*ges));
  rs = (secp256k1_scalar *) secp256k1_scratch_alloc(&ctx->error_callback, scratch, n * sizeof(*rs));
  rns = (secp256k1_scalar *) secp256k1_scratch_alloc(&ctx->error_callback, scratch, n * sizeof(*rns));
  ss = (secp256k1_scalar *) secp256k1_scratch_alloc(&ctx->error_callback, scratch, n * sizeof(*ss));
  if ( ges == NULL || rs == NULL || rns == NULL || ss == NULL) goto error;

  for (i = 0; i < n; ++i) {
    secp256k1_ecdsa_signature_load(ctx, &rs[i], &ss[i], sigs[i]);
    if (secp256k1_scalar_is_zero(&rs[i]) || secp256k1_scalar_is_zero(&ss[i])) goto error;
  }
  for (i = 0; i < pubkeys_n; ++i) {
    if(!secp256k1_pubkey_load(ctx, &ges[i], pubkeys[i])) goto error;
  }


  secp256k1_scalar_inv_all_var(rns, rs, n);

  for (i = 0; i < n; ++i) {
    secp256k1_scalar_set_b32(&m, msgs32[i], NULL);
    if(!secp256k1_ecdsa_sig_recover_four(&ctx->ecmult_ctx, four_gejs, &n_keys, &rs[i], &rns[i], &ss[i], &m)) goto error;
    l = 0; /* index how many were equal */
    for(j = 0; j < n_keys; ++j) { /* loop over four_gejs */
      secp256k1_fe_normalize_weak(&four_gejs[j].x);
      secp256k1_fe_normalize_weak(&four_gejs[j].y);
      for (k = 0; k < pubkeys_n; ++k) {  /* loop over pubkeys */
        if(ge_equals_gej_var(&ges[k], &four_gejs[j])) {
          pubkeys_out[i*4+l] = pubkeys[k];
          l++;
          break;
        }
      }
    }
  }

  secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
  return 1;

  error:
      secp256k1_scratch_apply_checkpoint(&ctx->error_callback, scratch, scratch_checkpoint);
      return 0;
}

#endif /* SECP256K1_MODULE_RECOVERY_MAIN_H */
