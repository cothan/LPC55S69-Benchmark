#include "randombytes.h"
#include "LPC55S69_cm33_core0.h"
#include "fsl_rng.h"

int randombytes(uint8_t *buf, size_t xlen)
{
    RNG_GetRandomData(RNG, buf, xlen);
    
    return 0;
}
