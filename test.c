#include <stdio.h>

#include "aead_aegis128l.h"

int
main(void)
{
    unsigned char k[32] = { 1 };
    unsigned char n[16] = { 2 };
    unsigned char m[32] = { 3 };
    unsigned char c[32 + crypto_aead_aegis128l_ABYTES];

    crypto_aead_aegis128l_encrypt(c, NULL, m, sizeof m, NULL, 0, NULL, n, k);
    if (crypto_aead_aegis128l_decrypt(m, NULL, NULL, c, sizeof c, NULL, 0, n, k) != 0) {
        puts("Decryption failed");
        return 1;
    }
    c[0] ^= 1;
    if (crypto_aead_aegis128l_decrypt(m, NULL, NULL, c, sizeof c, NULL, 0, n, k) != -1) {
        puts("Decryption should have failed");
        return 1;
    }
    return 0;
}