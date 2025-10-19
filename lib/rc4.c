#include "rc4.h"

/* KSA */
void rc4_init(uint8_t S[256], const uint8_t *key, size_t keylen) {
    for (int i = 0; i < 256; ++i) S[i] = (uint8_t)i;
    uint8_t j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (uint8_t)(j + S[i] + key[i % keylen]);
        /* swap S[i], S[j] */
        uint8_t tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }
}

/* PRGA: generate keystream and XOR in-place */
void rc4_crypt(uint8_t S[256], uint8_t *data, size_t datalen) {
    uint8_t i = 0, j = 0;
    for (size_t k = 0; k < datalen; ++k) {
        i = (uint8_t)(i + 1);
        j = (uint8_t)(j + S[i]);
        uint8_t tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        uint8_t K = S[(uint8_t)(S[i] + S[j])];
        data[k] ^= K;
    }
}
