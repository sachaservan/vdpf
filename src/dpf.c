// This is the 2-party FSS for point functions from:
// "Function Secret Sharing: Improvements and Extensions."
// by Boyle, Elette, Niv Gilboa, and Yuval Ishai.
// Proceedings of the 2016 ACM SIGSAC Conference on Computer and
// Communications Security. ACM, 2016.

// Implementation is partially based on:
// - https://github.com/SabaEskandarian/Express/tree/master/v2
// - https://github.com/ucbrise/dory/blob/master/src/c/dpf.h
// - https://github.com/sachaservan/private-ann/tree/main/pir/dpfc

#include "../include/dpf.h"
#include "../include/mmo.h"
#include "../include/common.h"
#include <openssl/rand.h>

void genDPF(
	EVP_CIPHER_CTX *ctx,
	int size,
	uint64_t index,
	unsigned char *k0,
	unsigned char *k1)
{
	uint128_t seeds0[size + 1];
	uint128_t seeds1[size + 1];
	int bits0[size + 1];
	int bits1[size + 1];

	uint128_t sCW[size];
	int tCW0[size];
	int tCW1[size];

	seeds0[0] = getRandomBlock();
	seeds1[0] = getRandomBlock();
	bits0[0] = 0;
	bits1[0] = 1;

	uint128_t s0[2], s1[2]; // 0=L,1=R
	int t0[2], t1[2];

	for (int i = 1; i <= size; i++)
	{
		dpfPRG(ctx, seeds0[i - 1], &s0[LEFT], &s0[RIGHT], &t0[LEFT], &t0[RIGHT]);
		dpfPRG(ctx, seeds1[i - 1], &s1[LEFT], &s1[RIGHT], &t1[LEFT], &t1[RIGHT]);

		int keep, lose;
		int indexBit = getbit(index, size, i);
		if (indexBit == 0)
		{
			keep = LEFT;
			lose = RIGHT;
		}
		else
		{
			keep = RIGHT;
			lose = LEFT;
		}

		sCW[i - 1] = s0[lose] ^ s1[lose];

		tCW0[i - 1] = t0[LEFT] ^ t1[LEFT] ^ indexBit ^ 1;
		tCW1[i - 1] = t0[RIGHT] ^ t1[RIGHT] ^ indexBit;

		if (bits0[i - 1] == 1)
		{
			seeds0[i] = s0[keep] ^ sCW[i - 1];
			if (keep == 0)
				bits0[i] = t0[keep] ^ tCW0[i - 1];
			else
				bits0[i] = t0[keep] ^ tCW1[i - 1];
		}
		else
		{
			seeds0[i] = s0[keep];
			bits0[i] = t0[keep];
		}

		if (bits1[i - 1] == 1)
		{
			seeds1[i] = s1[keep] ^ sCW[i - 1];
			if (keep == 0)
				bits1[i] = t1[keep] ^ tCW0[i - 1];
			else
				bits1[i] = t1[keep] ^ tCW1[i - 1];
		}
		else
		{
			seeds1[i] = s1[keep];
			bits1[i] = t1[keep];
		}
	}

	uint128_t sFinal0 = convert(&seeds0[size]);
	uint128_t sFinal1 = convert(&seeds1[size]);
	uint128_t lastCW = 1 ^ sFinal0 ^ sFinal1;

	// memcpy all the generated values into two keys
	k0[0] = 0;
	memcpy(&k0[1], seeds0, 16);
	k0[CWSIZE - 1] = bits0[0];
	for (int i = 1; i <= size; i++)
	{
		memcpy(&k0[CWSIZE * i], &sCW[i - 1], 16);
		k0[CWSIZE * i + CWSIZE - 2] = tCW0[i - 1];
		k0[CWSIZE * i + CWSIZE - 1] = tCW1[i - 1];
	}
	memcpy(&k0[INDEX_LASTCW], &lastCW, 16);
	memcpy(k1, k0, INDEX_LASTCW + 16);
	memcpy(&k1[1], seeds1, 16); // only value that is different from k0
	k1[0] = 1;
	k1[17] = bits1[0];
}

void batchEvalDPF(
	EVP_CIPHER_CTX *ctx,
	int size,
	bool b,
	unsigned char *k,
	uint64_t *in,
	uint64_t inl,
	uint8_t *out)
{

	// parse the key
	uint128_t seeds[size + 1];
	int bits[size + 1];
	uint128_t sCW[size + 1];
	int tCW0[size];
	int tCW1[size];

	// outter loop: iterate over all evaluation points
	for (int l = 0; l < inl; l++)
	{
		// parse the key
		memcpy(&seeds[0], &k[1], 16);
		bits[0] = b;

		for (int i = 1; i <= size; i++)
		{
			memcpy(&sCW[i - 1], &k[18 * i], 16);
			tCW0[i - 1] = k[18 * i + 16];
			tCW1[i - 1] = k[18 * i + 17];
		}

		uint128_t sL, sR;
		int tL, tR;
		for (int i = 1; i <= size; i++)
		{
			dpfPRG(ctx, seeds[i - 1], &sL, &sR, &tL, &tR);

			if (bits[i - 1] == 1)
			{
				sL = sL ^ sCW[i - 1];
				sR = sR ^ sCW[i - 1];
				tL = tL ^ tCW0[i - 1];
				tR = tR ^ tCW1[i - 1];
			}

			uint128_t xbit = getbit(in[l], size, i);

			// if (xbit == 0): seeds[i] = sL else seeds[i] = sR
			seeds[i] = (1 - xbit) * sL + xbit * sR;
			bits[i] = (1 - xbit) * tL + xbit * tR;
		}

		uint128_t res = convert(&seeds[size]);

		if (bits[size] == 1)
		{
			// correction word
			res = res ^ convert((uint128_t *)&k[INDEX_LASTCW]);
		}

		// copy block to byte output
		memcpy(&out[l * sizeof(uint128_t)], &res, sizeof(uint128_t));
	}
}

// evaluates the full DPF domain; much faster than
// batching the evaluation points since each level of the DPF tree
// is only expanded once.
void fullDomainDPF(
	EVP_CIPHER_CTX *ctx,
	int size,
	bool b,
	unsigned char *k,
	uint8_t *out)
{

	// dataShare is of size dataSize
	int numLeaves = 1 << size;
	int maxLayer = size;

	int currLevel = 0;
	int levelIndex = 0;
	int numIndexesInLevel = 2;

	int treeSize = 2 * numLeaves - 1;

	uint128_t *seeds = malloc(sizeof(uint128_t) * treeSize); // treesize too big to allocate on stack
	int *bits = malloc(sizeof(int) * treeSize);
	uint128_t sCW[maxLayer + 1];
	int tCW0[maxLayer + 1];
	int tCW1[maxLayer + 1];

	memcpy(seeds, &k[1], 16);
	bits[0] = b;

	for (int i = 1; i <= maxLayer; i++)
	{
		memcpy(&sCW[i - 1], &k[18 * i], 16);
		tCW0[i - 1] = k[CWSIZE * i + CWSIZE - 2];
		tCW1[i - 1] = k[CWSIZE * i + CWSIZE - 1];
	}

	uint128_t sL, sR;
	int tL, tR;
	for (int i = 1; i < treeSize; i += 2)
	{
		int parentIndex = 0;
		if (i > 1)
		{
			parentIndex = i - levelIndex - ((numIndexesInLevel - levelIndex) / 2);
		}

		dpfPRG(ctx, seeds[parentIndex], &sL, &sR, &tL, &tR);

		if (bits[parentIndex] == 1)
		{
			sL = sL ^ sCW[currLevel];
			sR = sR ^ sCW[currLevel];
			tL = tL ^ tCW0[currLevel];
			tR = tR ^ tCW1[currLevel];
		}

		int lIndex = i;
		int rIndex = i + 1;
		seeds[lIndex] = sL;
		bits[lIndex] = tL;
		seeds[rIndex] = sR;
		bits[rIndex] = tR;

		levelIndex += 2;
		if (levelIndex == numIndexesInLevel)
		{
			currLevel++;
			numIndexesInLevel *= 2;
			levelIndex = 0;
		}
	}

	uint128_t *outBlocks = (uint128_t *)out;
	for (int i = 0; i < numLeaves; i++)
	{
		int index = treeSize - numLeaves + i;

		uint128_t res = convert(&seeds[index]);

		if (bits[index] == 1)
		{
			// correction word
			res = res ^ convert((uint128_t *)&k[INDEX_LASTCW]);
		}

		// copy block to byte output
		outBlocks[i] = res;
	}

	free(bits);
	free(seeds);
}
