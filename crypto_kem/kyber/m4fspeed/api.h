#ifndef API_H
#define API_H

#include "params.h"

#define CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define CRYPTO_BYTES           KYBER_SSBYTES

#define CRYPTO_ALGNAME "Kyber768"
#define KYBER_NAMESPACE(s) pqcrystals_kyber_##s

#define crypto_kem_keypair KYBER_NAMESPACE(keypair)
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

#define crypto_kem_enc KYBER_NAMESPACE(enc)
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

#define crypto_kem_dec KYBER_NAMESPACE(dec)
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
