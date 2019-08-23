/**
 * Sign an ECDSA Signature
 * The message should be a hashed 32 bytes.
 * Input: msg -> pointer to 32 bytes message.
 * privkey -> pointer to 32 bytes private key.
 * Output: sig_out -> pointer to a 64 bytes buffer.
 * Returns:
 * 1 - Finished successfully.
 * 0 - Failed.
 */
int ecc_secp256k1_ecdsa_sign(unsigned char *sig_out,
                             const unsigned char *msg,
                             const unsigned char *privkey);

/**
 * Verify a ECDSA Signature
 * Accepts either compressed(33 btes) or uncompressed(65 bytes) public key. using the flag (1==compressed, 0==uncompressed).
 * Input: sig -> pointer to 64 bytes signature.
 * msg -> 32 bytes result of a hash. (***Make Sure you hash the message yourself! otherwise it's easily broken***)
 * pubkey -> pointer to 33 or 65 bytes pubkey depending on the compressed flag.
 * compressed -> 1 for compressed, 0 for uncompressed.
 * Returns:
 * 1 - The signature is valid.
 * 0 - Signature is not valid.
 * -1 - Some other problem.
 */
int ecc_secp256k1_ecdsa_verify(const unsigned char *sig,
                               const unsigned char *msg,
                               const unsigned char *pubkey,
                               int compressed);

/**
 * Sign a Schnorr Signature
 * The message should be a hashed 32 bytes.
 * Input: msg -> pointer to 32 bytes message.
 * privkey -> pointer to 32 bytes private key.
 * Output: sig_out -> pointer to a 64 bytes buffer.
 * Returns:
 * 1 - Finished successfully.
 * 0 - Failed.
 */
int ecc_secp256k1_schnorr_sign(unsigned char *sig_out,
                               const unsigned char *msg,
                               const unsigned char *privkey);

/**
 * Verify a Schnorr Signature
 * Accepts either compressed(33 btes) or uncompressed(65 bytes) public key. using the flag (1==compressed, 0==uncompressed).
 * Input: sig -> pointer to 64 bytes signature.
 * msg -> 32 bytes result of a hash. (***Make Sure you hash the message yourself! otherwise it's easily broken***)
 * pubkey -> pointer to 33 or 65 bytes pubkey depending on the compressed flag.
 * compressed -> 1 for compressed, 0 for uncompressed.
 * Returns:
 * 1 - The signature is valid.
 * 0 - Signature is not valid.
 * -1 - Some other problem.
 */
int ecc_secp256k1_schnorr_verify(const unsigned char *sig,
                                 const unsigned char *msg,
                                 const unsigned char *pubkey,
                                 int compressed);
