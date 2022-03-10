// Partially based on:
// - https://github.com/SabaEskandarian/Express/tree/master/v2
// - https://github.com/ucbrise/dory/blob/master/src/c/dpf.h
// - https://github.com/sachaservan/private-ann/tree/main/pir/dpfc

#ifndef _DPF
#define _DPF

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define FIELDSIZE 2
#define FIELDBITS 1

#define INDEX_LASTCW 18 * size + 18
#define CWSIZE 18

#define MMO_HASH_IN_1 2
#define MMO_HASH_OUT_1 4
#define MMO_HASH_IN_2 4
#define MMO_HASH_OUT_2 2

#define LEFT 0
#define RIGHT 1

#define FIELDMASK ((1L << FIELDBITS) - 1)

typedef struct Hash hash;
typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

// PRG cipher context
extern EVP_CIPHER_CTX *getDPFContext(uint8_t *);
extern void destroyContext(EVP_CIPHER_CTX *);

// DPF functions
extern void genDPF(EVP_CIPHER_CTX *ctx, int size, uint64_t index, unsigned char *k0, unsigned char *k1);
extern void batchEvalDPF(EVP_CIPHER_CTX *ctx, int size, bool b, unsigned char *k, uint64_t *in, uint64_t inl, uint8_t *out);
extern void fullDomainDPF(EVP_CIPHER_CTX *ctx, int size, bool b, unsigned char *k, uint8_t *out);

// VDPF functions
extern void genVDPF(EVP_CIPHER_CTX *ctx, struct Hash *hash, int size, uint64_t index, unsigned char *k0, unsigned char *k1);
extern void batchEvalVDPF(EVP_CIPHER_CTX *ctx, struct Hash *mmo_hash1, struct Hash *mmo_hash2, int size, bool b, unsigned char *k, uint64_t *in, uint64_t inl, uint8_t *out, uint8_t *pi);
extern void fullDomainVDPF(EVP_CIPHER_CTX *ctx, struct Hash *mmo_hash1, struct Hash *mmo_hash2, int size, bool b, unsigned char *k, uint8_t *out, uint8_t *proof);

#endif
