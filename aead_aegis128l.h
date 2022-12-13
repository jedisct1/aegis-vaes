#ifndef aead_aegis128l_H
#define aead_aegis128l_H

int crypto_aead_aegis128l_encrypt_detached(unsigned char *c, unsigned char *mac,
                                           unsigned long long *maclen_p, const unsigned char *m,
                                           unsigned long long mlen, const unsigned char *ad,
                                           unsigned long long adlen, const unsigned char *nsec,
                                           const unsigned char *npub, const unsigned char *k);

int crypto_aead_aegis128l_decrypt_detached(unsigned char *m, unsigned char *nsec,
                                           const unsigned char *c, unsigned long long clen,
                                           const unsigned char *mac, const unsigned char *ad,
                                           unsigned long long adlen, const unsigned char *npub,
                                           const unsigned char *k);

int crypto_aead_aegis128l_encrypt(unsigned char *c, unsigned long long *clen_p,
                                  const unsigned char *m, unsigned long long mlen,
                                  const unsigned char *ad, unsigned long long adlen,
                                  const unsigned char *nsec, const unsigned char *npub,
                                  const unsigned char *k);

int crypto_aead_aegis128l_decrypt(unsigned char *m, unsigned long long *mlen_p, unsigned char *nsec,
                                  const unsigned char *c, unsigned long long clen,
                                  const unsigned char *ad, unsigned long long adlen,
                                  const unsigned char *npub, const unsigned char *k);

#define crypto_aead_aegis128l_KEYBYTES         16U
#define crypto_aead_aegis128l_NSECBYTES        0U
#define crypto_aead_aegis128l_NPUBBYTES        16U
#define crypto_aead_aegis128l_ABYTES           16U
#define crypto_aead_aegis128l_MESSAGEBYTES_MAX ((1ULL << 61) - 1)

#endif