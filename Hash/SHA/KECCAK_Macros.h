#ifndef KECCAK_MACROS_H_
#define KECCAK_MACROS_H_

#define WIDTH(b) (b / 25)
#define LENGTH(w) (w * 25)

#define SWITCH_MAPS(a, b) \
	do { \
		unsigned char* aux = a; \
		a = b; \
		b = aux; \
	} while(0)

#define MAP(x, y, z) ((S[dim * (5 * (y) + (x)) + ((z) / 8)] & (1 << ((z) % 8))) > 0)
#define MAPPrime(x, y, z) SPrime[dim * (5 * (y) + (x)) + ((z) / 8)]

#define C(x, z) ((MAP(x, 0, z) ^ MAP(x, 1, z) ^ MAP(x, 2, z) ^ MAP(x, 3, z) ^ MAP(x, 4, z)) & 1)
#define D(x, z) ((C((x + 4) % 5, z) ^ C((x + 1) % 5, (z + w - 1) % w)) & 1)
#define THETA(x, y, z) ((MAP(x, y, z) ^ D(x, z)) & 1)

#define RHO(x, y, z) (MAP(x, y, (z + w - (((t + 1) * (t + 2) / 2) % w)) % w) & 1)

#define PI(x, y, z) (MAP((x + 3 * y) % 5, x, z) & 1)

#define CHI(x, y, z) ((MAP(x, y, z) ^ ((MAP((x + 1) % 5, y, z) ^ 1) & 1) & MAP((x + 2) % 5, y, z)) & 1)

#define TRUNC(s, x) (x & ((1 << s) - 1))

unsigned char rc(size_t t);

#endif
