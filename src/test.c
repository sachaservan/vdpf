#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include "../include/dpf.h"
#include "../include/mmo.h"

#define EVALSIZE 1 << 20
#define EVALDOMAIN 20
#define FULLEVALDOMAIN 20
#define MAXRANDINDEX 1ULL << FULLEVALDOMAIN

uint64_t randIndex()
{
    srand(time(NULL));
    return ((uint64_t)rand()) % (MAXRANDINDEX);
}

void testVDPF()
{
    // set up the DPF PRG
    int size = EVALDOMAIN;
    uint64_t secretIndex = randIndex();
    uint8_t *key = malloc(16);
    RAND_bytes(key, 16);
    EVP_CIPHER_CTX *ctx = getDPFContext(key);

    size_t outblocks = 4;
    uint128_t hashkey1;
    uint128_t hashkey2;
    RAND_bytes((uint8_t *)&hashkey1, sizeof(uint128_t));
    RAND_bytes((uint8_t *)&hashkey2, sizeof(uint128_t));

    // set up the MMO hash function
    struct Hash *mmo_hash1;
    struct Hash *mmo_hash2;
    mmo_hash1 = initMMOHash((uint8_t *)&hashkey1, outblocks);

    // gen VDPF keys (extra layer ==> key size is size+1)
    unsigned char *vk0 = malloc(INDEX_LASTCW + 16 + 16 * (outblocks));
    unsigned char *vk1 = malloc(INDEX_LASTCW + 16 + 16 * (outblocks));
    genVDPF(ctx, mmo_hash1, size, secretIndex, vk0, vk1);
    destroyMMOHash(mmo_hash1);
    // printf("finished genVDPF()\n");

    // generate batch of inputs to evaluate on
    size_t L = EVALSIZE;
    uint64_t *X = malloc(sizeof(uint64_t) * L);
    for (size_t i = 0; i < L; i++)
    {
        int anotherIndex = randIndex();
        if (anotherIndex == secretIndex)
        {
            continue;
        }

        X[i] = anotherIndex;
    }

    X[0] = secretIndex;

    uint128_t *shares0 = malloc(sizeof(uint128_t) * L);
    uint128_t *shares1 = malloc(sizeof(uint128_t) * L);
    uint128_t pi0[outblocks];
    uint128_t pi1[outblocks];

    // eval on server 0
    clock_t t;
    t = clock();
    mmo_hash1 = initMMOHash((uint8_t *)&hashkey1, outblocks);
    mmo_hash2 = initMMOHash((uint8_t *)&hashkey2, outblocks);
    batchEvalVDPF(ctx, mmo_hash1, mmo_hash2, size, false, vk0, X, L, (uint8_t *)shares0, (uint8_t *)&pi0[0]);
    t = clock() - t;
    destroyMMOHash(mmo_hash1);
    destroyMMOHash(mmo_hash2);

    // eval on server 1
    mmo_hash1 = initMMOHash((uint8_t *)&hashkey1, outblocks);
    mmo_hash2 = initMMOHash((uint8_t *)&hashkey2, outblocks);
    batchEvalVDPF(ctx, mmo_hash1, mmo_hash2, size, true, vk1, X, L, (uint8_t *)shares1, (uint8_t *)&pi1[0]);
    destroyMMOHash(mmo_hash1);
    destroyMMOHash(mmo_hash2);

    for (size_t i = 0; i < 2; i++) // output is 256 bits so 2 blocks
    {
        if (pi0[i] != pi1[i])
        {
            printf("FAIL (pi0 =/= pi1)\n");
            exit(0);
        }
    }

    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms
    printf("VDPF eval time (total) %f ms\n", time_taken);

    if (((shares0[0] + shares1[0]) % FIELDSIZE) != 1)
    {
        printf("FAIL (zero)\n");
        exit(0);
    }
    for (size_t i = 1; i < L; i++)
    {
        if (((shares0[i] + shares1[i]) % FIELDSIZE) != 0)
        {
            printf("FAIL (non-zero) at index %llx\n", X[i]);
            exit(0);
        }
    }

    free(vk0);
    free(vk1);
    free(X);
    printf("DONE\n\n");

    //************************************************
    // Test full domain evaluation optimization
    //************************************************
    printf("Testing full-domain evaluation optimization\n");

    mmo_hash1 = initMMOHash((uint8_t *)&hashkey1, outblocks);
    mmo_hash2 = initMMOHash((uint8_t *)&hashkey2, outblocks);

    size = FULLEVALDOMAIN; // evaluation will result in 2^size points
    int outl = 1 << size;
    secretIndex = randIndex();

    vk0 = malloc(INDEX_LASTCW + 16 + 16 * (outblocks));
    vk1 = malloc(INDEX_LASTCW + 16 + 16 * (outblocks));
    genVDPF(ctx, mmo_hash1, size, secretIndex, vk0, vk1);
    destroyMMOHash(mmo_hash1);

    shares0 = malloc(sizeof(uint128_t) * outl);
    shares1 = malloc(sizeof(uint128_t) * outl);

    mmo_hash1 = initMMOHash((uint8_t *)&hashkey1, outblocks);
    mmo_hash2 = initMMOHash((uint8_t *)&hashkey2, outblocks);

    t = clock();
    fullDomainVDPF(ctx, mmo_hash1, mmo_hash2, size, false, vk0, (uint8_t *)shares0, (uint8_t *)&pi0);
    t = clock() - t;
    time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms
    destroyMMOHash(mmo_hash1);
    destroyMMOHash(mmo_hash2);

    mmo_hash1 = initMMOHash((uint8_t *)&hashkey1, outblocks);
    mmo_hash2 = initMMOHash((uint8_t *)&hashkey2, outblocks);
    fullDomainVDPF(ctx, mmo_hash1, mmo_hash2, size, true, vk1, (uint8_t *)shares1, (uint8_t *)&pi1);
    destroyMMOHash(mmo_hash1);
    destroyMMOHash(mmo_hash2);

    printf("VDPF full-domain eval time (total) %f ms\n", time_taken);

    for (size_t i = 0; i < 2; i++)
    {
        if (pi0[i] != pi1[i])
        {
            printf("FAIL (pi0 =/= pi1)\n");
            exit(0);
        }
    }

    if (((shares0[secretIndex] + shares1[secretIndex]) % FIELDSIZE) != 1)
    {
        printf("FAIL (zero)\n");
        exit(0);
    }

    for (size_t i = 0; i < outl; i++)
    {
        if (i == secretIndex)
            continue;

        if (((shares0[i] + shares1[i]) % FIELDSIZE) != 0)
        {
            printf("FAIL (non-zero)\n");
            exit(0);
        }
    }

    destroyContext(ctx);
    printf("DONE\n\n");
}

void testDPF()
{
    int size = EVALDOMAIN;
    uint64_t secretIndex = randIndex();
    uint8_t *key = malloc(16);
    RAND_bytes(key, 16);
    EVP_CIPHER_CTX *ctx = getDPFContext(key);

    unsigned char *k0 = malloc(INDEX_LASTCW + 16);
    unsigned char *k1 = malloc(INDEX_LASTCW + 16);
    genDPF(ctx, size, secretIndex, k0, k1);
    // printf("finished genDPF()\n");

    size_t L = EVALSIZE;
    uint64_t *X = malloc(sizeof(uint64_t) * L);
    for (size_t i = 0; i < L; i++)
    {
        int anotherIndex = randIndex();
        if (anotherIndex == secretIndex)
        {
            continue;
        }

        X[i] = anotherIndex;
    }

    X[0] = secretIndex;

    //************************************************
    // Test point-by-pont evaluation
    //************************************************

    uint128_t *shares0 = malloc(sizeof(uint128_t) * L);
    uint128_t *shares1 = malloc(sizeof(uint128_t) * L);

    clock_t t;
    t = clock();
    batchEvalDPF(ctx, size, false, k0, X, L, (uint8_t *)shares0);
    t = clock() - t;
    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms
    printf("DPF eval time (total) %f ms\n", time_taken);

    batchEvalDPF(ctx, size, true, k1, X, L, (uint8_t *)shares1);

    if (((shares0[0] + shares1[0]) % FIELDSIZE) != 1)
    {
        printf("FAIL (zero)\n");
        exit(0);
    }
    for (size_t i = 1; i < L; i++)
    {
        if (((shares0[i] + shares1[i]) % FIELDSIZE) != 0)
        {
            printf("FAIL (non-zero) at %zu\n", i);
            exit(0);
        }
    }
    free(shares0);
    free(shares1);
    free(k0);
    free(k1);
    free(X);
    printf("DONE\n\n");

    //************************************************
    // Test full domain evaluation
    //************************************************
    printf("Testing full-domain evaluation optimization\n");

    size = FULLEVALDOMAIN; // evaluation will result in 2^size points
    int outl = 1 << size;
    secretIndex = randIndex();
    k0 = malloc(INDEX_LASTCW + 16);
    k1 = malloc(INDEX_LASTCW + 16);
    genDPF(ctx, size, secretIndex, k0, k1);

    // printf("Full domain = %i\n", outl);

    shares0 = malloc(sizeof(uint128_t) * outl);
    shares1 = malloc(sizeof(uint128_t) * outl);

    t = clock();
    fullDomainDPF(ctx, size, false, k0, (uint8_t *)shares0);
    t = clock() - t;
    time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

    fullDomainDPF(ctx, size, true, k1, (uint8_t *)shares1);

    printf("DPF full-domain eval time (total) %f ms\n", time_taken);

    if (((shares0[secretIndex] + shares1[secretIndex]) % FIELDSIZE) != 1)
    {
        printf("FAIL (zero)\n");
        exit(0);
    }

    for (size_t i = 0; i < outl; i++)
    {
        if (i == secretIndex)
            continue;

        if (((shares0[i] + shares1[i]) % FIELDSIZE) != 0)
        {
            printf("FAIL (non-zero)\n");
            exit(0);
        }
    }

    destroyContext(ctx);
    free(k0);
    free(k1);
    free(shares0);
    free(shares1);
    printf("DONE\n\n");
}

void testMMO()
{
    for (int i = 0; i < 100; i++)
    {

        uint128_t hashkey0;
        uint128_t hashkey1;
        RAND_bytes((uint8_t *)&hashkey0, sizeof(uint128_t));
        hashkey1 = hashkey0;

        struct Hash *hash0 = initMMOHash((uint8_t *)&hashkey0, 4);
        struct Hash *hash1 = initMMOHash((uint8_t *)&hashkey1, 4);

        uint128_t messages[2];
        RAND_bytes((uint8_t *)messages, sizeof(uint128_t) * 2);

        uint128_t **outputs0 = malloc(sizeof(uint128_t *) * 1000);
        for (int j = 0; j < 1000; j++)
        {
            uint128_t output[2];
            mmoHash2to4(hash0, (uint8_t *)&messages, (uint8_t *)&output);
            outputs0[j] = output;
        }

        uint128_t **outputs1 = malloc(sizeof(uint128_t *) * 1000);
        for (int j = 0; j < 1000; j++)
        {
            uint128_t output[2];
            mmoHash2to4(hash1, (uint8_t *)&messages, (uint8_t *)&output);
            outputs1[j] = output;
        }

        for (int j = 0; j < 1000; j++)
        {
            if (outputs0[j][0] != outputs1[j][0])
                printf("MMO failed hahing consistency\n");

            if (outputs0[j][1] != outputs1[j][1])
                printf("MMO failed hahing consistency\n");

            if (outputs0[j][2] != outputs1[j][2])
                printf("MMO failed hahing consistency\n");

            if (outputs0[j][3] != outputs1[j][3])
                printf("MMO failed hahing consistency\n");
        }

        destroyMMOHash(hash0);
        destroyMMOHash(hash1);
    }
}

int main(int argc, char **argv)
{

    int testTrials = 10;
    printf("******************************************\n");
    printf("Testing VDPF\n");
    for (int i = 0; i < testTrials; i++)
        testVDPF();
    printf("******************************************\n");
    printf("PASS\n");
    printf("******************************************\n\n");

    printf("******************************************\n");
    printf("Testing DPF\n");
    for (int i = 0; i < testTrials; i++)
        testDPF();
    printf("******************************************\n");
    printf("PASS\n");
    printf("******************************************\n\n");

    printf("******************************************\n");
    printf("Testing MMO\n");
    testMMO();
    printf("******************************************\n");
    printf("PASS\n");
    printf("******************************************\n\n");
}