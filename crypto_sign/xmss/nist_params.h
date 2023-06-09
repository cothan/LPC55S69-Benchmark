#ifndef NIST_PARAM_H
#define NIST_PARAM_H

#include "params.h"

#ifndef XMSSMT
#define XMSSMT 1
#endif

#ifndef LEVEL
#define LEVEL 0
#endif

#ifndef SHAKE
#define SHAKE 0
#endif


#if XMSSMT == 0
    /* 
    * Maximum signatures: 2^h = 2^10
    */
    #if LEVEL == 0

    #if SHAKE == 0
        #define XMSS_OID "XMSS-SHA2_10_256"
    #else
        #define XMSS_OID "XMSS-SHAKE_10_256"
    #endif

    #define XMSS_PUBLICKEYBYTES 64
    #define XMSS_SECRETKEYBYTES 2045

    #define XMSS_SIGNBYTES 2500

    /* 
    * Maximum signatures: 2^h = 2^16
    */
    #elif LEVEL == 1

    #if SHAKE == 0
        #define XMSS_OID "XMSS-SHA2_16_256"
    #else
        #define XMSS_OID "XMSS-SHAKE_16_256"
    #endif

    #define XMSS_PUBLICKEYBYTES 64
    #define XMSS_SECRETKEYBYTES 3149

    #define XMSS_SIGNBYTES 2692

    /* 
    * Maximum signatures: 2^h = 2^20
    */
    #elif LEVEL == 2

    #if SHAKE == 0
        #define XMSS_OID "XMSS-SHA2_20_256"
    #else
        #define XMSS_OID "XMSS-SHAKE_20_256"
    #endif

    #define XMSS_PUBLICKEYBYTES 64
    #define XMSS_SECRETKEYBYTES 3885

    #define XMSS_SIGNBYTES 2820


    #else

    #error "Unspecified LEVEL {0,1,2}"

    #endif
#else 
    /* 
    * Maximum signatures: 2^h = 2^20
    * XMSS^MT has bigger signature and secret key (secret is not transfer), but better speed
    */
    #if LEVEL == 0

    #if SHAKE == 0
        #define XMSS_OID "XMSSMT-SHA2_20/2_256"
    #else
        #define XMSS_OID "XMSSMT-SHAKE_20/2_256"
    #endif

    #define XMSS_PUBLICKEYBYTES 64
    #define XMSS_SECRETKEYBYTES 8078

    #define XMSS_SIGNBYTES 4963

    /* 
    * Maximum signatures: 2^h = 2^40
    * XMSS^MT has bigger signature and secret key (secret is not transfer), but better speed
    */
    #elif LEVEL == 1

    #if SHAKE == 0
        #define XMSS_OID "XMSSMT-SHA2_40/2_256"
    #else
        #define XMSS_OID "XMSSMT-SHAKE_40/2_256"
    #endif

    #define XMSS_PUBLICKEYBYTES 64
    #define XMSS_SECRETKEYBYTES 13600

    #define XMSS_SIGNBYTES 5605

    /* 
    * Maximum signatures: 2^h = 2^60
    * XMSS^MT has bigger signature and secret key (secret is not transfer), but better speed
    */
    #elif LEVEL == 2

    #if SHAKE == 0
        #define XMSS_OID "XMSSMT-SHA2_60/3_256"
    #else
        #define XMSS_OID "XMSSMT-SHAKE_60/3_256"
    #endif

    #define XMSS_PUBLICKEYBYTES 64
    #define XMSS_SECRETKEYBYTES 23317

    #define XMSS_SIGNBYTES 8392


    #else

    #error "Unspecified LEVEL {0,1,2}"

    #endif

#endif

#if XMSSMT == 1
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_KEYPAIR xmssmt_keypair
    #define XMSS_SIGN xmssmt_sign
    #define XMSS_SIGN_OPEN xmssmt_sign_open
    #define XMSS_REMAIN_SIG xmssmt_remain_signatures
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_STR_TO_OID xmss_str_to_oid
    #define XMSS_KEYPAIR xmss_keypair
    #define XMSS_SIGN xmss_sign
    #define XMSS_SIGN_OPEN xmss_sign_open
    #define XMSS_REMAIN_SIG xmss_remain_signatures
#endif

#define CRYPTO_PUBLIC_KEY (XMSS_PUBLICKEYBYTES + XMSS_OID_LEN)
#define CRYPTO_SECRET_KEY (XMSS_SECRETKEYBYTES + XMSS_OID_LEN)
#define CRYPTO_BYTES XMSS_SIGNBYTES

#endif
