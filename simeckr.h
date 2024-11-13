#ifndef SIMECK_R_H
#define SIMECK_R_H

#include <argon2.h> /* libargon2 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define ARGON_HASHLEN 32
#define ARGON_SALTLEN 16

#define MAXPWDLEN 32

#define SIMECK_DERIVED_KEY_LEN 4
#define SIMECK_R_MAX_ROUNDS 44

extern uint32_t SIMECK_R_ROUNDS; // 7

#define LROT32(x, r) (((x) << (r)) | ((x) >> (32 - (r))))

#define ROUND64(key, lft, rgt, tmp) do { \
    tmp = (lft); \
    lft = ((lft) & LROT32((lft), 5)) ^ LROT32((lft), 1) ^ (rgt) ^ (key); \
    rgt = (tmp); \
} while (0)

typedef struct {
	uint32_t it1, it2;
	uint32_t NL, NR;
	uint8_t Sbox1[256], Sbox2[256], Sbox3[256];
	uint8_t loop;
	uint32_t derived_key_r[SIMECK_DERIVED_KEY_LEN];
	uint32_t t_cost;      // 2-pass computation
	uint32_t m_cost;      // 64 mebibytes memory usage
	uint32_t parallelism; // number of threads and lanes
} simeckr_ctx;

void RC4D_KSA(uint8_t k[], uint8_t L, uint8_t *S);
void SimeckInit(simeckr_ctx *CTX, const char *password);
void SimeckEncrypt(uint32_t *v, uint32_t *k);
void SimeckREncrypt(const uint32_t Pt[], uint32_t *Ct, simeckr_ctx *CTX); 

void copy_bytes_to_uint32(const uint8_t *source, uint32_t *destination, size_t elements);
void split_uint64_to_uint32(uint64_t input, uint32_t *low, uint32_t *high);

#endif
