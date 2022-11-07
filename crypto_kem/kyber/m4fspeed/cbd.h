#ifndef CBD_H
#define CBD_H

#include "poly.h"

#if KYBER_SEC == 1

void cbd_eta1(poly *r, const unsigned char *buf, int add);
void cbd_eta2(poly *r, const unsigned char *buf, int add);

#else

void cbd(poly *r, const unsigned char *buf, int add);

#endif

#endif
