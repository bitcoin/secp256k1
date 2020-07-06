/**********************************************************************
 * Copyright (c) 2017 Tomas van der Wansem                            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/


#ifndef _SECP256K1_MULTISET__
# define _SECP256K1_MULTISET__

# include "secp256k1.h"


# ifdef __cplusplus
extern "C" {
# endif


/** Opaque multiset; this is actually a group element **/
typedef struct {
    unsigned char d[96];
} secp256k1_multiset;



/** Initialize a multiset
 *  The resulting multiset the multiset for no data elements
 *
 *  Returns: 1: success
 *           0: invalid parameter
 *  Args:    ctx:      pointer to a context object (cannot be NULL)
 *  Out:     multiset: the resulting multiset
 */
SECP256K1_API int secp256k1_multiset_init(
  const secp256k1_context* ctx,
  secp256k1_multiset *multiset
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);


/** Adds an element to a multiset from single data element
 *
 *  Returns: 1: success
 *           0: invalid parameter
 *  Args:    ctx:      pointer to a context object (cannot be NULL)
 *  Out:     multiset: the multiset to update
 *  In:      input:    the data to add
 *           inputLen: the size of the data to add
 */
SECP256K1_API int secp256k1_multiset_add(
  const secp256k1_context* ctx,
  secp256k1_multiset *multiset,
  const unsigned char *input,
  size_t inputLen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Removes an element from a multiset
 *
 *  Returns: 1: success
 *           0: invalid parameter
 *  Args:    ctx:      pointer to a context object (cannot be NULL)
 *  Out:     multiset: the multiset to update
 *  In:      input:    the data to remove
 *           inputLen: the size of the data to remove
 */
SECP256K1_API int secp256k1_multiset_remove(
  const secp256k1_context* ctx,
  secp256k1_multiset *multiset,
  const unsigned char *input,
  size_t inputLen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);



/** Combines two multisets
 *
 *  Returns: 1: success
 *           0: invalid parameter
 *  Args:    ctx:      pointer to a context object (cannot be NULL)
 *  In/Out:  multiset: the multiset to which the input must be added
 *  In:      input:    the multiset to add
 */
SECP256K1_API int secp256k1_multiset_combine(
  const secp256k1_context* ctx,
  secp256k1_multiset *multiset,
  const secp256k1_multiset *input

) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);


/** Converts a multiset to a hash
 *
 *  Returns: 1: success
 *           0: invalid parameter
 *  Args:    ctx:      pointer to a context object (cannot be NULL)
 *  Out:     hash:     the resulting 32-byte hash
 *  In:      multiset: the multiset to hash
 */
SECP256K1_API int secp256k1_multiset_finalize(
  const secp256k1_context* ctx,
  unsigned char *resultHash,
  const secp256k1_multiset *multiset
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);



# ifdef __cplusplus
}
# endif

#endif
