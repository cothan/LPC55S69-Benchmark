#ifndef API_H
#define API_H

#define KYBER_SEC 5

#ifndef KYBER_SEC
#define KYBER_SEC 3
#endif

#if KYBER_SEC == 1
#include "api1.h"
#include "params1.h"

#elif KYBER_SEC == 3
#include "api3.h"
#include "params3.h"

#elif KYBER_SEC == 5
#include "api5.h"
#include "params5.h"

#endif

#endif