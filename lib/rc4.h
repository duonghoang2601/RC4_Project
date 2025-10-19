#ifndef RC4_H
#define RC4_H

#include <stddef.h>
#include <stdint.h>

/*
 * Minimal RC4 API
 *
 * rc4_init: initialize RC4 state with key
 * rc4_crypt: encrypt/decrypt data in-place (RC4 is symmetric)
 *
 * Usage:
 *   uint8_t S[256];
 *   rc4_init(S, key_bytes, key_len);
 *   rc4_crypt(S, data, data_len);
 *
 * Note: rc4_crypt modifies the internal state S (PRGA), so if you want to
 * produce the same keystream again, re-init with rc4_init.
 */

void rc4_init(uint8_t S[256], const uint8_t *key, size_t keylen);
void rc4_crypt(uint8_t S[256], uint8_t *data, size_t datalen);

#endif /* RC4_H */
