// Implementation of the Matyas–Meyer–Oseas one-way compression function.
// See https://crypto.stackexchange.com/questions/56247/matyas-meyer-oseas-for-super-fast-single-block-hash-function
// and https://en.wikipedia.org/wiki/One-way_compression_function

#include "../include/mmo.h"
#include <openssl/rand.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

uint128_t *prg(uint128_t seed, uint64_t outblocks)
{
    EVP_CIPHER_CTX *randCtx;
    if (!(randCtx = EVP_CIPHER_CTX_new()))
        printf("errors occured in creating PRG context\n");

    if (1 != EVP_EncryptInit_ex(randCtx, EVP_aes_128_ecb(), NULL, (uint8_t *)&seed, NULL))
        printf("errors occured in PRG seeding\n");

    EVP_CIPHER_CTX_set_padding(randCtx, 0);

    int len;
    uint128_t *output = malloc(sizeof(uint128_t) * outblocks);
    for (uint64_t i = 0; i < outblocks; i++)
    {
        output[i] = 0;
    }

    if (1 != EVP_EncryptUpdate(randCtx, (uint8_t *)output, &len, (uint8_t *)output, sizeof(uint128_t) * outblocks))
        printf("errors occurred in generating PRG randomness\n");

    EVP_CIPHER_CTX_free(randCtx);

    return output;
}

struct Hash *initMMOHash(uint8_t *seed, uint64_t outblocks)
{
    EVP_CIPHER_CTX **mmoCtx = malloc(sizeof(EVP_CIPHER_CTX *) * outblocks);
    struct Hash *hash = malloc(sizeof(struct Hash));
    uint128_t seedint = 0;
    memcpy(&seedint, seed, sizeof(uint128_t));
    uint128_t *seeds = prg(seedint, outblocks); // expand the key into k seeds

    for (size_t k = 0; k < outblocks; k++)
    {
        if (!(mmoCtx[k] = EVP_CIPHER_CTX_new()))
            printf("errors occured in creating context\n");

        if (1 != EVP_EncryptInit_ex(mmoCtx[k], EVP_aes_128_ecb(), NULL, (uint8_t *)&seeds[k], NULL))
            printf("errors occurred in randomness init\n");

        EVP_CIPHER_CTX_set_padding(mmoCtx[k], 0);
    }

    hash->mmoCtx = mmoCtx;
    hash->outblocks = outblocks;
    return hash;
}

void destroyMMOHash(struct Hash *hash)
{
    for (size_t k = 0; k < hash->outblocks; k++)
    {
        EVP_CIPHER_CTX_free(hash->mmoCtx[k]);
    }
    free(hash);
}

// Matyas-Meyer-Oseas technique for instantiating a one-way compression function
// takes 2 blocks and outputs 4 blocks
void mmoHash2to4(struct Hash *hash, uint8_t *input, uint8_t *output)
{
    uint128_t *outputblocks = (uint128_t *)output;
    uint128_t *inputblocks = (uint128_t *)input;

    int len = 0;
    if (1 != EVP_EncryptUpdate(hash->mmoCtx[0], (uint8_t *)&outputblocks[0], &len, (uint8_t *)input, 16 * 2))
        printf("errors occurred in generating randomness\n");

    outputblocks[0] ^= inputblocks[0];
    outputblocks[1] ^= inputblocks[1];

    if (1 != EVP_EncryptUpdate(hash->mmoCtx[1], (uint8_t *)&outputblocks[2], &len, (uint8_t *)input, 16 * 2))
        printf("errors occurred in generating randomness\n");

    outputblocks[2] ^= inputblocks[0];
    outputblocks[3] ^= inputblocks[0];
}

// Matyas-Meyer-Oseas technique for instantiating a one-way compression function
// takes 4 blocks and outputs 4 blocks
void mmoHash4to4(struct Hash *hash, uint8_t *input, uint8_t *output)
{
    uint128_t *outputblocks = (uint128_t *)output;
    uint128_t *inputblocks = (uint128_t *)input;

    int len = 0;
    if (1 != EVP_EncryptUpdate(hash->mmoCtx[0], (uint8_t *)&outputblocks[0], &len, (uint8_t *)input, 16 * 4))
        printf("errors occurred in generating AES hash\n");

    outputblocks[0] ^= inputblocks[0];
    outputblocks[1] ^= inputblocks[1];
    outputblocks[2] ^= inputblocks[2];
    outputblocks[3] ^= inputblocks[3];
}
