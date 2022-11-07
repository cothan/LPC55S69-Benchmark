/*
 * Copyright 2016-2022 NXP
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * o Redistributions of source code must retain the above copyright notice, this list
 *   of conditions and the following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 * o Neither the name of NXP Semiconductor, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file    LPC55S69_Project_minimal_float2.c
 * @brief   Application entry point.
 */
#include <stdio.h>
#include "board.h"
#include "peripherals.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "LPC55S69_cm33_core0.h"
#include "fsl_debug_console.h"
/* TODO: insert other include files here. */
#include "init.h"

#define CHECK 1

#if CHECK == 0
#include "dilithium/m4f/api.h"
#elif CHECK == 1
#include "kyber/m4fspeed/api.h"
#include "kyber/m4fspeed/params.h"
#elif CHECK == 2
#include "xmss/api.h"
#include "xmss/nist_params.h"
#elif CHECK == 3
#include "falcon-512/m4-ct/api.h"
#elif CHECK == 4
#include "hawk/hawk.h"
#endif

/* TODO: insert other definitions and declarations here. */
#define CC_PUBLIC(TYPE, COUNTER, CODE)                                  \
    do                                                                  \
    {                                                                   \
        uint32_t ii;                                                    \
        uint64_t start = 0, end = 0;                                    \
        int ret = 0;                                                    \
                                                                        \
        start = cpucycles();                                            \
        for (ii = 0; ii < COUNTER && !ret; ii++)                        \
        {                                                               \
            ret = CODE;                                                 \
        }                                                               \
        end = cpucycles();                                              \
        /*PRINTF("\r\ns,e,c: %lu, %lu, %u\r\n", start, end, COUNTER);*/ \
        end = end - start;                                              \
        if (ret != 0)                                                   \
        {                                                               \
            PRINTF(TYPE ": error\r\n");                                 \
        }                                                               \
        else                                                            \
        {                                                               \
            PRINTF(TYPE ": %6.2f kc", (float)end / (COUNTER * 1000));   \
            PRINTF("\r\n");                                             \
        }                                                               \
        fflush(stdout);                                                 \
    } while (0)

#define TIME_PUBLIC(TYPE, COUNTER, CODE)                                                 \
    do                                                                                   \
    {                                                                                    \
        uint32_t ii;                                                                     \
        uint64_t tsc;                                                                    \
        int ret;                                                                         \
                                                                                         \
        ret = 0;                                                                         \
        tsc = cpucycles();                                                               \
        for (ii = 0; ii < COUNTER && !ret; ii++)                                         \
        {                                                                                \
            ret = CODE;                                                                  \
        }                                                                                \
        tsc = cpucycles() - tsc;                                                         \
        tsc *= 1000;                                                                     \
        if (ret != 0)                                                                    \
        {                                                                                \
            PRINTF(TYPE ": error\r\n");                                                  \
            PRINTF(TYPE ": %6.2f ms", (float)tsc / COUNTER / CLOCK_GetCoreSysClkFreq()); \
            PRINTF("\r\n");                                                              \
        }                                                                                \
        else                                                                             \
        {                                                                                \
            PRINTF(TYPE ": %6.2f ms", (float)tsc / COUNTER / CLOCK_GetCoreSysClkFreq()); \
            PRINTF("\r\n");                                                              \
        }                                                                                \
    } while (0)

#if CHECK == 0
void bench_Dilithium(void)
{
    uint8_t sk[DILITHIUM_SECRETKEYBYTES], pk[DILITHIUM_PUBLICKEYBYTES];

    PRINTF("\r\nWorking with DILITHIUM-%d\r\n", DILITHIUM_MODE);

    TIME_PUBLIC("pqcrystals_dilithium_keypair", 100,
                pqcrystals_dilithium_crypto_sign_keypair(pk, sk));

    uint8_t sig[DILITHIUM_CRYPTO_BYTES];
    uint8_t m[] = "This is a test from SandboxAQ";
    size_t siglen = 0;

    TIME_PUBLIC("pqcrystals_dilithium_signature", 100,
                pqcrystals_dilithium_signature(sig, &siglen, m, sizeof(m), sk));

    PRINTF("Benchmark Verify\r\n");

    TIME_PUBLIC()
}
#elif CHECK == 1
void bench_Kyber(void)
{
    uint8_t sk[CRYPTO_SECRETKEYBYTES], pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES], ss1[CRYPTO_BYTES] = {0}, ss2[CRYPTO_BYTES] = {0};

    PRINTF("\r\nWorking with KYBER-%d\r\n", KYBER_K);

    TIME_PUBLIC("pqcrystals_kyber_keypair", 100,
                pqcrystals_kyber_keypair(pk, sk));

    TIME_PUBLIC("pqcrystals_kyber_enc", 100,
                pqcrystals_kyber_enc(ct, ss1, pk));

    TIME_PUBLIC("pqcrystals_kyber_dec", 100,
                pqcrystals_kyber_dec(ss2, ct, sk));

    PRINTF("\r\n");
    for (int i = 0; i < CRYPTO_BYTES; i++)
    {
        PRINTF("%02x", ss1[i]);
    }
    PRINTF("\r\n");
    for (int i = 0; i < CRYPTO_BYTES; i++)
    {
        PRINTF("%02x", ss2[i]);
    }
    PRINTF("\r\n");

    if (memcmp(ss1, ss2, CRYPTO_BYTES))
    {
        PRINTF("ERROR\r\n");
    }
    else
    {
        PRINTF("GOOD\r\n");
    }
}
#elif CHECK == 2
void bench_XMSS(void)
{
    uint8_t sk[CRYPTO_SECRET_KEY], pk[CRYPTO_PUBLIC_KEY];
    uint8_t m[] = "This is a test from SandboxAQ";
    uint8_t mout[XMSS_SIGNBYTES + sizeof(m)] = {0};
    uint8_t sm[XMSS_SIGNBYTES + sizeof(m)];
    size_t smlen = 0, mout_len = 0;

    PRINTF("\r\nWorking with %s\r\n", XMSS_OID);

    TIME_PUBLIC("xmss_crypto_keypair", 1,
                xmss_crypto_keypair(pk, sk));

    TIME_PUBLIC("xmss_crypto_sign", 100,
                xmss_crypto_sign(sm, &smlen, m, sizeof(m), sk));

    TIME_PUBLIC("xmss_crypto_sign_open", 100,
                xmss_crypto_sign_open(mout, &mout_len, sm, smlen, pk));

    if (mout_len != sizeof(m))
    {
        PRINTF("return size ERROR: %lu - %lu\r\n", mout_len, sizeof(m));
    }

    if (memcmp(m, mout, sizeof(m)))
    {
        PRINTF("ERROR\r\n");
    }
    else
    {
        PRINTF("GOOD\r\n");
    }
}
#elif CHECK == 3
void bench_Falcon(void)
{
    uint8_t sk[CRYPTO_SECRETKEYBYTES], pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t m[] = "This is a test from SandboxAQ";
    uint8_t sm[CRYPTO_BYTES + sizeof(m)];
    uint8_t mout[CRYPTO_BYTES + sizeof(m)];
    size_t smlen = 0, mout_len = 0;

    PRINTF("\r\nWorking with %s\r\n", CRYPTO_ALGNAME);

    TIME_PUBLIC("falcon_crypto_sign_keypair", 1,
                falcon_crypto_sign_keypair(pk, sk));

    TIME_PUBLIC("falcon_crypto_sign", 100,
                falcon_crypto_sign(sm, &smlen, m, sizeof(m), sk));

    TIME_PUBLIC("falcon_crypto_sign_open", 100,
                falcon_crypto_sign_open(mout, &mout_len, sm, smlen, pk));

    if (mout_len != sizeof(m))
    {
        PRINTF("return size ERROR: %lu - %lu\r\n", mout_len, sizeof(m));
    }

    if (memcmp(m, mout, sizeof(m)))
    {
        PRINTF("ERROR\r\n");
    }
    else
    {
        PRINTF("GOOD\r\n");
    }
}
#elif CHECK == 4

typedef struct
{
    unsigned logn;
    shake256_context rng;
    uint8_t *tmp, *pk, *sk, *esk, *sig;
    size_t tmp_len, sig_len;
} bench_context;

void bench_Hawk(size_t logn)
{
    bench_context bc;
    PRINTF("\r\nWorking with HAWK-%4u\r\n", 1u << logn);

    bc.logn = logn;
    uint8_t seed[48];
    RNG_GetRandomData(RNG, seed, 48);
    shake256_init_prng_from_seed(&bc.rng, seed, sizeof(seed));
    shake256_flip(&bc.rng);

    bc.sk = malloc(HAWK_SECKEY_SIZE(logn));
    bc.pk = malloc(HAWK_PUBKEY_SIZE[logn]);
    bc.esk = malloc(HAWK_EXPANDEDKEY_SIZE(logn));
    bc.sig = malloc(HAWK_SIG_COMPACT_MAXSIZE(logn));
    bc.sig_len = 0;

    bc.tmp_len = HAWK_TMPSIZE_KEYGEN(logn);
    bc.tmp = malloc(bc.tmp_len);

    TIME_PUBLIC("hawk_keygen_make", 1,
                hawk_keygen_make(&bc.rng, bc.logn,
                                 bc.sk, HAWK_SECKEY_SIZE(bc.logn),
                                 bc.pk, HAWK_PUBKEY_SIZE[bc.logn],
                                 bc.tmp, bc.tmp_len));

    free(bc.tmp);
    bc.tmp_len = HAWK_TMPSIZE_SIGNDYN_NTT(logn);
    bc.tmp = malloc(bc.tmp_len);
    bc.sig_len = HAWK_SIG_COMPACT_MAXSIZE(bc.logn);
    TIME_PUBLIC("hawk_sign_dyn", 1,
                hawk_sign_dyn(&bc.rng,
                              bc.sig, &bc.sig_len, HAWK_SIG_COMPACT,
                              bc.sk, HAWK_SECKEY_SIZE(bc.logn),
                              "data", 4, bc.tmp, bc.tmp_len));

    free(bc.tmp);
    bc.tmp_len = HAWK_TMPSIZE_VERIFY_NTT(logn);
    bc.tmp = malloc(bc.tmp_len);
    TIME_PUBLIC("hawk_verify", 1,
                hawk_verify(bc.sig, bc.sig_len, HAWK_SIG_COMPACT,
                            bc.pk, HAWK_PUBKEY_SIZE[bc.logn],
                            "data", 4, bc.tmp, bc.tmp_len));
    free(bc.tmp);
    free(bc.pk);
    free(bc.sk);
    free(bc.esk);
    free(bc.sig);
}
#endif

/*
 * @brief   Application entry point.
 */
int main(void)
{

    init();
    init_crypto();

#if CHECK == 0
    bench_Dilithium();
#elif CHECK == 1
    bench_Kyber();
#elif CHECK == 2
    bench_XMSS();
#elif CHECK == 3
    bench_Falcon();
#elif CHECK == 4
    bench_Hawk(9U);
    bench_Hawk(10U);
#endif

    PRINTF("Infinite loop\r\n");
    /* Force the counter to be placed into memory. */
    static volatile int i = 0;
    /* Enter an infinite loop, just incrementing a counter. */
    while (1)
    {
        i++;
        /* 'Dummy' NOP to allow source level single stepping of
            tight while() loop */
        __asm volatile("nop");
    }
    return 0;
}
