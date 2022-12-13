#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __clang__
#pragma clang attribute push(__attribute__((target("vaes,avx2"))), apply_to = function)
#elif defined(__GNUC__)
#pragma GCC target("vaes,avx2")
#endif

#include <immintrin.h>

#include "aead_aegis128l.h"

#ifndef CRYPTO_ALIGN
#if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#define CRYPTO_ALIGN(x) __declspec(align(x))
#else
#define CRYPTO_ALIGN(x) __attribute__((aligned(x)))
#endif
#endif

#define AES_BLOCK_LOAD(A)      _mm_loadu_si128((const __m128i *) (const void *) (A))
#define AES_BLOCK_LOAD2(A)     _mm256_loadu_si256((const __m256i *) (const void *) (A))
#define AES_BLOCK_STORE(A, B)  _mm_storeu_si128((__m128i *) (void *) (A), (B))
#define AES_BLOCK_STORE2(A, B) _mm256_storeu_si256((__m256i *) (void *) (A), (B))

static inline void
aegis128l_update(__m256i *const state2, const __m256i d)
{
    const __m128i d1 = _mm256_extracti128_si256(d, 0);
    const __m128i d2 = _mm256_extracti128_si256(d, 1);

    const __m256i t3 = _mm256_permute2x128_si256(state2[3], state2[2], 0x03);
    const __m256i t2 = _mm256_permute2x128_si256(state2[2], state2[1], 0x03);
    const __m256i t1 = _mm256_permute2x128_si256(state2[1], state2[0], 0x03);
    const __m256i t0 = _mm256_permute2x128_si256(state2[0], state2[3], 0x03);

    state2[3] = _mm256_aesenc_epi128(t3, state2[3]);
    state2[2] = _mm256_aesenc_epi128(t2, state2[2]);
    state2[1] = _mm256_aesenc_epi128(t1, state2[1]);
    state2[0] = _mm256_aesenc_epi128(t0, state2[0]);

    state2[2] = _mm256_xor_si256(state2[2], _mm256_zextsi128_si256(d2));
    state2[0] = _mm256_xor_si256(state2[0], _mm256_zextsi128_si256(d1));
}

static void
aegis128l_init(const unsigned char *key, const unsigned char *nonce, __m256i *const state2)
{
    static CRYPTO_ALIGN(32)
        const uint8_t c0_[] = { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1,
                                0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd };
    static CRYPTO_ALIGN(32)
        const uint8_t c1_[] = { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d,
                                0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 };
    __m256i           d;
    const __m128i     c0 = AES_BLOCK_LOAD(c0_);
    const __m128i     c1 = AES_BLOCK_LOAD(c1_);
    const __m128i     k  = AES_BLOCK_LOAD(key);
    const __m128i     n  = AES_BLOCK_LOAD(nonce);
    int               i;

    state2[0] = _mm256_set_m128i(c0, _mm_xor_si128(k, n));
    state2[1] = _mm256_set_m128i(c0, c1);
    state2[2] = _mm256_set_m128i(_mm_xor_si128(k, c1), _mm_xor_si128(k, n));
    state2[3] = _mm256_set_m128i(_mm_xor_si128(k, c1), _mm_xor_si128(k, c0));

    d = _mm256_set_m128i(k, n);
    for (i = 0; i < 10; i++) {
        aegis128l_update(state2, d);
    }
}

static void
aegis128l_mac(unsigned char *mac, unsigned long long adlen, unsigned long long mlen,
              __m256i *const state2)
{
    __m256i d;
    __m256i tmp2;
    __m128i tmp;
    int     i;

    tmp = _mm_set_epi64x(mlen << 3, adlen << 3);
    tmp = _mm_xor_si128(tmp, _mm256_extracti128_si256(state2[1], 0));
    d   = _mm256_broadcastsi128_si256(tmp);

    for (i = 0; i < 7; i++) {
        aegis128l_update(state2, d);
    }

    tmp2 = _mm256_xor_si256(state2[0], state2[1]);
    tmp2 = _mm256_xor_si256(
        tmp2,
        _mm256_xor_si256(state2[2], _mm256_inserti128_si256(state2[3], _mm_setzero_si128(), 1)));
    tmp = _mm256_extracti128_si256(tmp2, 0);
    tmp = _mm_xor_si128(tmp, _mm256_extracti128_si256(tmp2, 1));

    AES_BLOCK_STORE(mac, tmp);
}

static inline void
aegis128l_absorb(const unsigned char *const src, __m256i *const state2)
{
    const __m256i msg = AES_BLOCK_LOAD2(src);

    aegis128l_update(state2, msg);
}

static inline void
aegis128l_enc(unsigned char *const dst, const unsigned char *const src, __m256i *const state2)
{
    __m256i msg;
    __m256i t, t62, t15, t26, t37;

    msg = AES_BLOCK_LOAD2(src);
    t62 = _mm256_permute2x128_si256(state2[1], state2[3], 0x02);
    t15 = _mm256_permute2x128_si256(state2[2], state2[0], 0x13);
    t26 = _mm256_permute2x128_si256(state2[3], state2[1], 0x02);
    t37 = _mm256_permute2x128_si256(state2[3], state2[1], 0x13);
    t   = _mm256_xor_si256(t62, t15);
    t   = _mm256_xor_si256(t, _mm256_xor_si256(_mm256_and_si256(t26, t37), msg));
    AES_BLOCK_STORE2(dst, t);

    aegis128l_update(state2, msg);
}

static inline void
aegis128l_dec(unsigned char *const dst, const unsigned char *const src, __m256i *const state2)
{
    __m256i ct;
    __m256i t, t62, t15, t26, t37;

    ct  = AES_BLOCK_LOAD2(src);
    t62 = _mm256_permute2x128_si256(state2[1], state2[3], 0x02);
    t15 = _mm256_permute2x128_si256(state2[2], state2[0], 0x13);
    t26 = _mm256_permute2x128_si256(state2[3], state2[1], 0x02);
    t37 = _mm256_permute2x128_si256(state2[3], state2[1], 0x13);
    t   = _mm256_xor_si256(t62, t15);
    t   = _mm256_xor_si256(t, _mm256_xor_si256(_mm256_and_si256(t26, t37), ct));
    AES_BLOCK_STORE2(dst, t);

    aegis128l_update(state2, t);
}

int
crypto_aead_aegis128l_encrypt_detached(unsigned char *c, unsigned char *mac,
                                       unsigned long long *maclen_p, const unsigned char *m,
                                       unsigned long long mlen, const unsigned char *ad,
                                       unsigned long long adlen, const unsigned char *nsec,
                                       const unsigned char *npub, const unsigned char *k)
{
    __m256i                        state2[4];
    CRYPTO_ALIGN(32) unsigned char src[32];
    CRYPTO_ALIGN(32) unsigned char dst[32];
    unsigned long long             i;

    (void) nsec;
    aegis128l_init(k, npub, state2);

    for (i = 0ULL; i + 32ULL <= adlen; i += 32ULL) {
        aegis128l_absorb(ad + i, state2);
    }
    if (adlen & 0x1f) {
        memset(src, 0, 32);
        memcpy(src, ad + i, adlen & 0x1f);
        aegis128l_absorb(src, state2);
    }
    for (i = 0ULL; i + 32ULL <= mlen; i += 32ULL) {
        aegis128l_enc(c + i, m + i, state2);
    }
    if (mlen & 0x1f) {
        memset(src, 0, 32);
        memcpy(src, m + i, mlen & 0x1f);
        aegis128l_enc(dst, src, state2);
        memcpy(c + i, dst, mlen & 0x1f);
    }

    aegis128l_mac(mac, adlen, mlen, state2);

    if (maclen_p != NULL) {
        *maclen_p = 16ULL;
    }
    return 0;
}

int
crypto_aead_aegis128l_decrypt_detached(unsigned char *m, unsigned char *nsec,
                                       const unsigned char *c, unsigned long long clen,
                                       const unsigned char *mac, const unsigned char *ad,
                                       unsigned long long adlen, const unsigned char *npub,
                                       const unsigned char *k)
{
    __m256i                        state2[4];
    CRYPTO_ALIGN(32) unsigned char src[32];
    CRYPTO_ALIGN(32) unsigned char dst[32];
    CRYPTO_ALIGN(32) unsigned char computed_mac[16];
    __m128i                        v;
    unsigned long long             i;
    unsigned long long             mlen;
    int                            ret;

    (void) nsec;
    mlen = clen;
    aegis128l_init(k, npub, state2);

    for (i = 0ULL; i + 32ULL <= adlen; i += 32ULL) {
        aegis128l_absorb(ad + i, state2);
    }
    if (adlen & 0x1f) {
        memset(src, 0, 32);
        memcpy(src, ad + i, adlen & 0x1f);
        aegis128l_absorb(src, state2);
    }
    if (m != NULL) {
        for (i = 0ULL; i + 32ULL <= mlen; i += 32ULL) {
            aegis128l_dec(m + i, c + i, state2);
        }
    } else {
        for (i = 0ULL; i + 32ULL <= mlen; i += 32ULL) {
            aegis128l_dec(dst, c + i, state2);
        }
    }
    if (mlen & 0x1f) {
        __m256i t;

        memset(src, 0, 32);
        memcpy(src, c + i, mlen & 0x1f);
        aegis128l_dec(dst, src, state2);
        if (m != NULL) {
            memcpy(m + i, dst, mlen & 0x1f);
        }
        memset(dst, 0, mlen & 0x1f);

        t = AES_BLOCK_LOAD2(dst);
        state2[0] =
            _mm256_xor_si256(state2[0], _mm256_zextsi128_si256(_mm256_extracti128_si256(t, 0)));
        state2[2] =
            _mm256_xor_si256(state2[2], _mm256_zextsi128_si256(_mm256_extracti128_si256(t, 1)));
    }

    aegis128l_mac(computed_mac, adlen, mlen, state2);

    v   = _mm_cmpeq_epi64(AES_BLOCK_LOAD(computed_mac), AES_BLOCK_LOAD(mac));
    ret = ((int) (_mm_extract_epi64(v, 0) & _mm_extract_epi64(v, 1) & 1)) - 1;

    if (m == NULL) {
        return ret;
    }
    if (ret != 0) {
        memset(m, 0, mlen);
        return -1;
    }
    return 0;
}

int
crypto_aead_aegis128l_encrypt(unsigned char *c, unsigned long long *clen_p, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *ad,
                              unsigned long long adlen, const unsigned char *nsec,
                              const unsigned char *npub, const unsigned char *k)
{
    unsigned long long clen = 0ULL;
    int                ret;

    if (mlen > crypto_aead_aegis128l_MESSAGEBYTES_MAX) {
        return -1;
    }
    ret = crypto_aead_aegis128l_encrypt_detached(c, c + mlen, NULL, m, mlen, ad, adlen, nsec, npub,
                                                 k);
    if (clen_p != NULL) {
        if (ret == 0) {
            clen = mlen + 16ULL;
        }
        *clen_p = clen;
    }
    return ret;
}

int
crypto_aead_aegis128l_decrypt(unsigned char *m, unsigned long long *mlen_p, unsigned char *nsec,
                              const unsigned char *c, unsigned long long clen,
                              const unsigned char *ad, unsigned long long adlen,
                              const unsigned char *npub, const unsigned char *k)
{
    unsigned long long mlen = 0ULL;
    int                ret  = -1;

    if (clen >= 16ULL) {
        ret = crypto_aead_aegis128l_decrypt_detached(m, nsec, c, clen - 16ULL, c + clen - 16ULL, ad,
                                                     adlen, npub, k);
    }
    if (mlen_p != NULL) {
        if (ret == 0) {
            mlen = clen - 16ULL;
        }
        *mlen_p = mlen;
    }
    return ret;
}

#ifdef __clang__
#pragma clang attribute pop
#endif
