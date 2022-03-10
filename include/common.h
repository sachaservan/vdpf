#ifndef _COMMON
#define _COMMON

#include <stdint.h>
#include <openssl/evp.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

static inline uint128_t reverse_lsb(uint128_t input)
{
	return input ^ 1;
}

static inline uint128_t lsb(uint128_t input)
{
	return input & 1;
}

static inline uint8_t seed_lsb(uint128_t input)
{
	return (input & 2) >> 1;
}

static inline uint128_t set_lsb_zero(uint128_t input)
{
	int lsb = (input & 1);
	if (lsb == 1)
	{
		return reverse_lsb(input);
	}
	else
	{
		return input;
	}
}

static inline int getbit(uint128_t x, int size, int b)
{
	return ((x) >> (size - b)) & 1;
}

static inline uint128_t correct(uint128_t raw0, uint128_t raw1, int t)
{
	if (t == 0)
		return raw0;
	return raw0 ^ raw1;
}

static inline uint128_t convert(uint128_t *raw)
{
	uint128_t r = *((uint128_t *)(raw));
	return r;
}

static void printBytes(void *p, int num)
{
	unsigned char *c = (unsigned char *)p;
	for (int i = 0; i < num; i++)
	{
		printf("%02x", c[i]);
	}
	printf("\n");
}

EVP_CIPHER_CTX *getDPFContext(uint8_t *key);
void destroyContext(EVP_CIPHER_CTX *ctx);
uint128_t getRandomBlock();
void dpfPRG(EVP_CIPHER_CTX *ctx, uint128_t input, uint128_t *output1, uint128_t *output2, int *bit1, int *bit2);

#endif
