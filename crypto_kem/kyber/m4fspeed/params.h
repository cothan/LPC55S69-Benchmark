#ifndef PARAMS_H
#define PARAMS_H

#include "api.h"

#if KYBER_SEC == 1
#include "params1.h"

#elif KYBER_SEC == 3
#include "params3.h"

#elif KYBER_SEC == 5
#include "params5.h"

#endif

#endif