#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../lib/rc4.h"

/* Usage: ./rc4-decrypt <key> <hex-ciphertext>
   Example:
     ./rc4-decrypt SecretKey 5cd95228b6524bcc8d655834de9936f8968987ce76f9484d1008e0c8ca4a951f8c702e7fa0fe9c916e0d
*/

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static unsigned char *hex_to_bytes(const char *hex, size_t *out_len) {
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0) return NULL;
    *out_len = hlen / 2;
    unsigned char *buf = malloc(*out_len);
    if (!buf) return NULL;
    for (size_t i = 0; i < *out_len; ++i) {
        int hi = hexval(hex[2*i]);
        int lo = hexval(hex[2*i+1]);
        if (hi < 0 || lo < 0) { free(buf); return NULL; }
        buf[i] = (unsigned char)((hi << 4) | lo);
    }
    return buf;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <key> <hex-ciphertext>\n", argv[0]);
        return 1;
    }
    const char *key = argv[1];
    const char *hex = argv[2];

    size_t keylen = strlen(key);
    size_t ct_len = 0;
    unsigned char *buf = hex_to_bytes(hex, &ct_len);
    if (!buf) {
        fprintf(stderr, "Invalid hex input\n");
        return 2;
    }

    uint8_t S[256];
    rc4_init(S, (const uint8_t*)key, keylen);
    rc4_crypt(S, buf, ct_len);

    /* Print decrypted plaintext as UTF-8 string */
    fwrite(buf, 1, ct_len, stdout);
    printf("\n");

    free(buf);
    return 0;
}
