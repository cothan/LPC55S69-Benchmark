#include "api.h"
#include "params.h"
#include "nist_params.h"
#include "xmss.h"

#if DEBUG
#include <stdio.h>
#endif

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    xmss_params params;
    uint32_t oid;
    int ret = 0;

    ret |= XMSS_STR_TO_OID(&oid, XMSS_OID);
    if (ret)
    {
#if DEBUG
        printf("Did not recognize %s!\n", XMSS_OID);
#endif
        return -1;
    }

    ret |= XMSS_PARSE_OID(&params, oid);
    if (ret)
    {
#if DEBUG
        printf("Could not parse OID for %s!\n", XMSS_OID);
#endif
        return -1;
    }
#if DEBUG
    printf("sklen, pklen, siglen = %llu, %u, %u\n", params.sk_bytes, params.pk_bytes, params.sig_bytes);
#endif

    ret |= XMSS_KEYPAIR(pk, sk, oid);
    if (ret)
    {
#if DEBUG
        printf("Error generating keypair %d\n", ret);
#endif
        return -1;
    }

    return 0;
}

int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen, unsigned char *sk)
{
    int ret = XMSS_SIGN(sk, sm, smlen, m, mlen);
    if (ret)
    {
#if DEBUG
        printf("Error generating signature %d\n", ret);
#endif
        return -1;
    }

    return 0;
}

int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen, const unsigned char *pk)
{
    if (XMSS_SIGN_OPEN(m, mlen, sm, smlen, pk))
    {
#if DEBUG
        printf("Error verifying signature %d\n", ret);
#endif
        return -1;
    }

    return 0;
}

int crypto_remaining_signatures(unsigned long long *remain, const unsigned char *sk)
{
    if (XMSS_REMAIN_SIG(remain, sk))
    {
#if DEBUG
        printf("Error counting remaining signatures\n");
#endif
        return -1;
    }
    return 0;
}
