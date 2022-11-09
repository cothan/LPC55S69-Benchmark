/* Based on the public domain implementation in
 * crypto_hash/sha512/ref/ from http://bench.cr.yp.to/supercop.html
 * by D. J. Bernstein */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "sha2.h"
#include "init.h"

void sha256_inc_init(hashcrypt_hash_ctx_t *ctx)
{
    HASHCRYPT_SHA_Init(HASHCRYPT, ctx, kHASHCRYPT_Sha256);
}

void sha256_inc_blocks(hashcrypt_hash_ctx_t *ctx, const uint8_t *in, size_t inblocks)
{
    HASHCRYPT_SHA_Update(HASHCRYPT, ctx, in, inblocks << 5);
}

void sha256_inc_finalize(uint8_t *out, hashcrypt_hash_ctx_t *ctx, const uint8_t *in, size_t inlen)
{
    size_t outlen;
    HASHCRYPT_SHA_Update(HASHCRYPT, ctx, in, inlen);
    HASHCRYPT_SHA_Finish(HASHCRYPT, ctx, out, &outlen);
}

/**
 * mgf1 function based on the SHA-256 hash function
 * Note that inlen should be sufficiently small that it still allows for
 * an array to be allocated on the stack. Typically 'in' is merely a seed.
 * Outputs outlen number of bytes
 */
void mgf1_256(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen)
{
    SPX_VLA(uint8_t, inbuf, inlen+4);
    unsigned char outbuf[SPX_SHA256_OUTPUT_BYTES];
    unsigned long i;

    memcpy(inbuf, in, inlen);

    /* While we can fit in at least another full block of SHA256 output.. */
    for (i = 0; (i+1)*SPX_SHA256_OUTPUT_BYTES <= outlen; i++) {
        u32_to_bytes(inbuf + inlen, i);
        sha256(out, inbuf, inlen + 4);
        out += SPX_SHA256_OUTPUT_BYTES;
    }
    /* Until we cannot anymore, and we fill the remainder. */
    if (outlen > i*SPX_SHA256_OUTPUT_BYTES) {
        u32_to_bytes(inbuf + inlen, i);
        sha256(outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - i*SPX_SHA256_OUTPUT_BYTES);
    }
}

/**
 * Absorb the constant pub_seed using one round of the compression function
 * This initializes state_seeded and state_seeded_512, which can then be
 * reused in thash
 **/
