#ifndef _MMO
#define _MMO

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

struct Hash
{
   EVP_CIPHER_CTX **mmoCtx;
   size_t outblocks;
};
typedef struct hash Hash;

// PRF cipher context
extern struct Hash *initMMOHash(uint8_t *seed, uint64_t outblocks);
extern void destroyMMOHash(struct Hash *hash);

// MMO functions
extern void mmoHash2to4(struct Hash *hash, uint8_t *input, uint8_t *output);
extern void mmoHash4to4(struct Hash *hash, uint8_t *input, uint8_t *output);

#endif
