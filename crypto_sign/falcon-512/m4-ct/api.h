#include <stddef.h>

#define CRYPTO_SECRETKEYBYTES   1281
#define CRYPTO_PUBLICKEYBYTES   897
#define CRYPTO_BYTES            690

#define CRYPTO_ALGNAME          "Falcon-512"
#define FALCON_NAMESPACE(s)     falcon_##s

#define crypto_sign_keypair FALCON_NAMESPACE(crypto_sign_keypair)
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

#define crypto_sign FALCON_NAMESPACE(crypto_sign)
int crypto_sign(unsigned char *sm, size_t *smlen,
	const unsigned char *m, size_t mlen,
	const unsigned char *sk);

#define crypto_sign_open FALCON_NAMESPACE(crypto_sign_open)
int crypto_sign_open(unsigned char *m, size_t *mlen,
	const unsigned char *sm, size_t smlen,
	const unsigned char *pk);
