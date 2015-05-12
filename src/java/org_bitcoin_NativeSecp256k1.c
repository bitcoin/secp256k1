#include <stdlib.h>
#include "org_bitcoin_NativeSecp256k1.h"
#include "include/secp256k1.h"

JNIEXPORT jlong JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1init_1context
  (JNIEnv* env, jclass classObject)
{
  secp256k1_context_t *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

  (void)classObject;(void)env;

  return (jlong)ctx;
}

JNIEXPORT void JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1destroy_1context
  (JNIEnv* env, jclass classObject, jlong ctx_l)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;

  secp256k1_context_destroy(ctx);

  (void)classObject;(void)env;
}

JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1verify
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint sigLen, jint pubLen)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;

  unsigned char* data = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

  (void)classObject;

  return secp256k1_ecdsa_verify(ctx, data, data+32, sigLen, data+32+sigLen, pubLen);
}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1sign
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;
  unsigned char* data = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  unsigned char* secKey = (unsigned char*) (data + 32);

  jobjectArray retArray;
  jbyteArray sigArray, intsByteArray;
  unsigned char intsarray[2];

  unsigned char sig[72];
  int siglen = 72;

  int ret = secp256k1_ecdsa_sign(ctx, data, sig, &siglen, secKey, NULL, NULL );

  intsarray[0] = siglen;
  intsarray[1] = ret;

  retArray = (*env)->NewObjectArray(env, 2,
    (*env)->FindClass(env, "[B"),
    (*env)->NewByteArray(env, 1));

  sigArray = (*env)->NewByteArray(env, siglen);
  (*env)->SetByteArrayRegion(env, sigArray, 0, siglen, (jbyte*)sig);
  (*env)->SetObjectArrayElement(env, retArray, 0, sigArray);

  intsByteArray = (*env)->NewByteArray(env, 2);
  (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
  (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

  (void)classObject;

  return retArray;
}

JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1seckey_1verify
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;
  unsigned char* secKey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

  (void)classObject;

  return secp256k1_ec_seckey_verify(ctx, secKey);
}

JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1pubkey_1verify
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint pubLen)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;
  unsigned char* pubKey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

  (void)classObject;

  return secp256k1_ec_pubkey_verify(ctx, pubKey, pubLen);
}

JNIEXPORT jbyteArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1pubkey_1create
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint compressed)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;
  unsigned char* secKey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

  unsigned char pubkey[65];
  int pubkeyLen = 65;

  jobjectArray retArray;
  jbyteArray pubkeyArray, intsByteArray;
  unsigned char intsarray[2];

  int ret = secp256k1_ec_pubkey_create(ctx, pubkey, &pubkeyLen, secKey, compressed );

  intsarray[0] = pubkeyLen;
  intsarray[1] = ret;

  retArray = (*env)->NewObjectArray(env, 2,
    (*env)->FindClass(env, "[B"),
    (*env)->NewByteArray(env, 1));

  pubkeyArray = (*env)->NewByteArray(env, pubkeyLen);
  (*env)->SetByteArrayRegion(env, pubkeyArray, 0, pubkeyLen, (jbyte*)pubkey);
  (*env)->SetObjectArrayElement(env, retArray, 0, pubkeyArray);

  intsByteArray = (*env)->NewByteArray(env, 2);
  (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
  (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

  (void)classObject;

  return retArray;

}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1pubkey_1decompress
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint pubLen)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;

  unsigned char* pubkey = (unsigned char*) malloc(sizeof(unsigned char)*65);

  unsigned char* temp = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

  int i, ret;
  jobjectArray retArray;
  jbyteArray pubkeyArray, intsByteArray;
  unsigned char intsarray[2];

  for(i = 0; i < pubLen; i++) pubkey[i] = temp[i];

  ret = secp256k1_ec_pubkey_decompress(ctx, pubkey, &pubLen);

  intsarray[0] = pubLen;
  intsarray[1] = ret;

  retArray = (*env)->NewObjectArray(env, 2,
    (*env)->FindClass(env, "[B"),
    (*env)->NewByteArray(env, 1));

  pubkeyArray = (*env)->NewByteArray(env, pubLen);
  (*env)->SetByteArrayRegion(env, pubkeyArray, 0, pubLen, (jbyte*)pubkey);
  (*env)->SetObjectArrayElement(env, retArray, 0, pubkeyArray);

  intsByteArray = (*env)->NewByteArray(env, 2);
  (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
  (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

  (void)classObject;

  return retArray;
}

/*
JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1pubkey_1export
  (JNIEnv *, jclass, jobject, jlong, jint);

JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1pubkey_1import
  (JNIEnv *, jclass, jobject, jlong, jint);

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1sign_1compact__Ljava_nio_ByteBuffer_2J
  (JNIEnv *, jclass, jobject, jlong);

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1sign_1compact__Ljava_nio_ByteBuffer_2JI
  (JNIEnv *, jclass, jobject, jlong, jint);
*/
