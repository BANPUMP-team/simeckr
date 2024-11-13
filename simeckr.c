#include "simeckr.h"

uint32_t SIMECK_R_ROUNDS;

/* 
 * RC4D_KSA is from https://link.springer.com/chapter/10.1007/978-3-030-64758-2_2
 */
void RC4D_KSA(uint8_t k[], uint8_t L, uint8_t *S) {
    int i,j=0;
    uint8_t aux;

    for (i=0; i<256; i++) S[i] = i;

    j = 0;
    for (i=0; i<256; i++) {
        j = (j + S[(i + k[i % L]) % 256] + k[i % L]) % 256;
	    aux=S[i]; S[i]=S[j]; S[j]=aux;
    }
}

void copy_bytes_to_uint32(const uint8_t *source, uint32_t *destination, size_t elements) {
    typedef union {
        uint32_t value;
	    uint8_t parts[4];
    } CopyUnion;
	
    for (size_t i = 0; i < elements; ++i) {
        CopyUnion u;

        for (int j = 0; j < 4; ++j) {
            u.parts[j] = source[i * 4 + j]; // Copy 4 bytes at a time
	    }

	    destination[i] = u.value;
    }
}

void split_uint64_to_uint32(uint64_t input, uint32_t *low, uint32_t *high) {
    *low = (uint32_t)(input & 0xFFFFFFFF);
    *high = (uint32_t)(input >> 32);
}

void SimeckInit(simeckr_ctx *CTX, const char *password) {
    int i;
    uint8_t *pwd = (uint8_t *)password;
    uint32_t pwdlen;
    uint32_t derived_key[SIMECK_DERIVED_KEY_LEN];
    uint8_t hash[ARGON_HASHLEN];
    uint8_t salt[ARGON_SALTLEN];
    uint8_t K[12]; 

    CTX->NL = 0; 
    CTX->NR = 0; 
    CTX->it1 = 0; 
    CTX->it2 = 0; 

    memset(salt, 0x00, ARGON_SALTLEN);
    pwdlen = strlen((char *)pwd); 

    CTX->t_cost = 20;           // 2-pass computation
    CTX->m_cost = (1<<16);      // 64 mebibytes memory usage
    CTX->parallelism = 1;       // number of threads and lanes
			   
    argon2i_hash_raw(CTX->t_cost, CTX->m_cost, CTX->parallelism, pwd, pwdlen, salt, ARGON_SALTLEN, hash, ARGON_HASHLEN);
    copy_bytes_to_uint32(hash, derived_key, SIMECK_DERIVED_KEY_LEN); // 4 * 32 = 128 bits

    for (i=0;i<12;i++) K[i]=hash[i+12];
    RC4D_KSA(K, 12, CTX->Sbox1);

    argon2i_hash_raw(CTX->t_cost, CTX->m_cost, CTX->parallelism, hash, ARGON_HASHLEN, salt, ARGON_SALTLEN, hash, ARGON_HASHLEN);
    for (i=0;i<12;i++) K[i]=hash[i+12];
    RC4D_KSA(K, 12, CTX->Sbox2);

    argon2i_hash_raw(CTX->t_cost, CTX->m_cost, CTX->parallelism, hash, ARGON_HASHLEN, salt, ARGON_SALTLEN, hash, ARGON_HASHLEN);
    for (i=0;i<12;i++) K[i]=hash[i+12];
    RC4D_KSA(K, 12, CTX->Sbox3);
}

void SimeckEncrypt(uint32_t *v, uint32_t *k) {

    int idx;
    uint32_t ciphertext[2];
    ciphertext[0] = v[0];
    ciphertext[1] = v[1];
    uint32_t temp;

    uint32_t constant = 0xFFFFFFFC;
    uint64_t sequence = 0x938BCA3083F;

    for (idx = 0; idx < SIMECK_R_ROUNDS; idx++) {
        ROUND64(
                k[0],
                ciphertext[1],
                ciphertext[0],
                temp
        );

        constant &= 0xFFFFFFFC;
        constant |= sequence & 1;
        sequence >>= 1;
        ROUND64(
                constant,
                k[1],
                k[0],
                temp
        );

        // rotate the LFSR of keys
        temp = k[1];
        k[1] = k[2];
        k[2] = k[3];
        k[3] = temp;
    }

    v[0] = ciphertext[0] ^ v[0];
    v[1] = ciphertext[1] ^ v[1];
}

void SimeckREncrypt(const uint32_t Pt[], uint32_t *Ct, simeckr_ctx *CTX) { 
    uint32_t i, aux;
    uint32_t x, y;
    uint32_t wbuf[2];

    x = CTX->NL; 
    y = CTX->NR;
    wbuf[1] = x; 
    wbuf[0] = y;

    Ct[0] = (wbuf[0] << 24) | (wbuf[0] >> 24) | ((wbuf[0] << 8) & 0xFF0000) | ((wbuf[0] >> 8) & 0xFF00); // y
    Ct[1] = (wbuf[1] << 24) | (wbuf[1] >> 24) | ((wbuf[1] << 8) & 0xFF0000) | ((wbuf[1] >> 8) & 0xFF00); // x
    
    SimeckEncrypt(Ct, CTX->derived_key_r);

    x = Ct[1]; 
    y = Ct[0];
    
    aux = x; 
    x = y; 
    y = aux;

    CTX->NR++; 

    y = CTX->Sbox1[y >> 24 & 0xFF] << 24 | CTX->Sbox1[y >> 16 & 0xFF] << 16 | CTX->Sbox1[y >> 8 & 0xFF] << 8 | CTX->Sbox1[y & 0xFF];
    Ct[0] ^= y ^ Pt[0];

    x = CTX->Sbox1[x >> 24 & 0xFF] << 24 | CTX->Sbox1[x >> 16 & 0xFF] << 16 | CTX->Sbox1[x >> 8 & 0xFF] << 8 | CTX->Sbox1[x & 0xFF];
    Ct[1] ^= x ^ Pt[1];

    // Update Sbox substitution operation follows
    CTX->it1++; 
    CTX->it2++;
    if (CTX->it1 == 2000) {
        for (i = 0; i < 256; i++) 
            CTX->Sbox1[i] = CTX->Sbox2[CTX->Sbox1[i]];
        CTX->it1 = 0;
        if (CTX->it2 == 2000 * 2000) {
            for (i = 0; i < 256; i++) 
                CTX->Sbox2[i] = CTX->Sbox3[CTX->Sbox2[i]];
            CTX->it2 = 0;
        }
    }
}
