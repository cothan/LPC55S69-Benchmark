#ifndef INIT_H
#define INIT_H

#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"
#include "fsl_clock.h"
#include "fsl_power.h"
// #include "fsl_casper.h"
#include "fsl_hashcrypt.h"
#include "LPC55S69_cm33_core0.h"
#include "fsl_rng.h"
#include "mbedtls/ecdsa.h"

void init(void);
void init_crypto(void);

void sha256(unsigned char *out, const unsigned char *in, unsigned long long inlen);

uint64_t cpucycles(void);

#endif
