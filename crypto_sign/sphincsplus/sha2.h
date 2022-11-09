#ifndef SPX_SHA2_H
#define SPX_SHA2_H

#include "params.h"

#define SPX_SHA256_BLOCK_BYTES 64
#define SPX_SHA256_OUTPUT_BYTES 32  /* This does not necessarily equal SPX_N */

#define SPX_SHA512_BLOCK_BYTES 128
#define SPX_SHA512_OUTPUT_BYTES 64

#if SPX_SHA256_OUTPUT_BYTES < SPX_N
    #error Linking against SHA-256 with N larger than 32 bytes is not supported
#endif

#define SPX_SHA256_ADDR_BYTES 22

#include <stddef.h>
#include <stdint.h>
#include "init.h"

void sha256_inc_init(hashcrypt_hash_ctx_t *ctx);
void sha256_inc_blocks(hashcrypt_hash_ctx_t *ctx, const uint8_t *in, size_t inblocks);
void sha256_inc_finalize(uint8_t *out, hashcrypt_hash_ctx_t *ctx, const uint8_t *in, size_t inlen);

void mgf1_256(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen);

#endif
