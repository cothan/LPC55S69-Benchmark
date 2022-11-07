#include "init.h"

/*
 * Init HASHCRYPT (SHA2 + AES), CASPER (ECC), and RNG
 */
void init_crypto(void)
{
    HASHCRYPT_Init(HASHCRYPT);
    // CASPER_Init(CASPER);
    RNG_Init(RNG);
}

void sha256(unsigned char *out,
            const unsigned char *in, unsigned long long inlen)
{
	size_t outlen;
    HASHCRYPT_SHA(HASHCRYPT, kHASHCRYPT_Sha256, in, inlen, out, &outlen);
}
void init(void)
{
    /* Init board hardware. */
    /* set BOD VBAT level to 1.65V */
    POWER_SetBodVbatLevel(kPOWER_BodVbatLevel1650mv, kPOWER_BodHystLevel50mv, false);

    BOARD_InitBootPins();
    BOARD_InitBootClocks();
    BOARD_InitBootPeripherals();
#ifndef BOARD_INIT_DEBUG_CONSOLE_PERIPHERAL
    /* Init FSL debug console. */
    BOARD_InitDebugConsole();
#endif
#if !defined(DONT_ENABLE_FLASH_PREFETCH)
    /* enable flash prefetch for better performance */
    SYSCON->FMCCR |= SYSCON_FMCCR_PREFEN_MASK;
#endif
    SysTick_Config(CLOCK_GetCoreSysClkFreq() / 1000U); /* 1 ms period */
}

static volatile uint32_t s_MsCount = 0U;

/*!
 * @brief Milliseconds counter since last POR/reset.
 */
void SysTick_Handler(void)
{
    s_MsCount++;
}

uint64_t cpucycles(void)
{
    uint32_t currMsCount;
    uint32_t currTick;
    uint32_t loadTick;

    do
    {
        currMsCount = s_MsCount;
        currTick = SysTick->VAL;
    } while (currMsCount != s_MsCount);

    loadTick = CLOCK_GetCoreSysClkFreq() / 1000U;
    return (((uint64_t)currMsCount) * loadTick) + loadTick - currTick;
}
