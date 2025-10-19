#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../lib/rc4.h"

/* main chỉ gọi hàm từ header/library.
   Usage: ./rc4-encrypt <key> "<plaintext>"
   Example: ./rc4-encrypt SecretKey "Hanoi University of Science and Technology"
*/

static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        printf("%02x", data[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <key> \"<plaintext>\"\n", argv[0]);
        return 1;
    }

    const char *key = argv[1];
    const char *plaintext = argv[2];

    size_t keylen = strlen(key);
    size_t len = strlen(plaintext);

    uint8_t *buf = malloc(len);
    if (!buf) return 2;
    memcpy(buf, plaintext, len);

    uint8_t S[256];
    rc4_init(S, (const uint8_t*)key, keylen);
    rc4_crypt(S, buf, len);

    /* Output ciphertext as hex */
    print_hex(buf, len);

    free(buf);
    return 0;
}
