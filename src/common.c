#include "../include/dpf.h"
#include "../include/mmo.h"
#include "../include/common.h"

#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

EVP_CIPHER_CTX *getDPFContext(uint8_t *key)
{
    EVP_CIPHER_CTX *randCtx;
    if (!(randCtx = EVP_CIPHER_CTX_new()))
        printf("errors occured in creating context\n");
    if (1 != EVP_EncryptInit_ex(randCtx, EVP_aes_128_ecb(), NULL, key, NULL))
        printf("errors occured in randomness init\n");
    EVP_CIPHER_CTX_set_padding(randCtx, 0);
    return randCtx;
}

void destroyContext(EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER_CTX_free(ctx);
}

uint128_t getRandomBlock()
{
    static uint8_t *randKey = NULL;
    static EVP_CIPHER_CTX *randCtx;
    static uint128_t counter = 0;

    if (!randKey)
    {
        randKey = (uint8_t *)malloc(16);

        if (!(randCtx = EVP_CIPHER_CTX_new()))
            printf("errors ocurred in creating context\n");
        if (!RAND_bytes(randKey, 16))
        {
            printf("failed to seed randomness\n");
        }
        if (1 != EVP_EncryptInit_ex(randCtx, EVP_aes_128_ecb(), NULL, randKey, NULL))
            printf("errors ocurred in randomness init\n");

        EVP_CIPHER_CTX_set_padding(randCtx, 0);
    }

    int len = 0;
    uint128_t output = 0;
    if (1 != EVP_EncryptUpdate(randCtx, (uint8_t *)&output, &len, (uint8_t *)&counter, 16))
        printf("errors ocurred in generating randomness\n");

    counter++;
    return output;
}

// this is the PRG used for the DPF
void dpfPRG(EVP_CIPHER_CTX *ctx, uint128_t input, uint128_t *output1, uint128_t *output2, int *bit1, int *bit2)
{
    input = set_lsb_zero(input);

    uint128_t stashin[2];
    stashin[0] = input;
    stashin[1] = reverse_lsb(input);

    int len = 0;
    uint128_t stash[2];

    if (1 != EVP_EncryptUpdate(ctx, (uint8_t *)&stash[0], &len, (uint8_t *)&stashin[0], 32))
        printf("errors occured in encrypt\n");

    stash[0] = stash[0] ^ input;
    stash[1] = stash[1] ^ input;
    stash[1] = reverse_lsb(stash[1]);

    *bit1 = lsb(stash[0]);
    *bit2 = lsb(stash[1]);

    *output1 = set_lsb_zero(stash[0]);
    *output2 = set_lsb_zero(stash[1]);
}
