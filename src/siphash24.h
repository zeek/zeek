
#ifndef SIPHASH24_H
#define SIPHASH24_H

#define SIPHASH_KEYLEN 16
#define SIPHASH_HASHLEN 8

extern "C" {
int _siphash(uint8_t *out, const uint8_t *in, uint64_t inlen, const uint8_t *k);
}

// [Bro] Wrapper for better type-safety.
inline void siphash(uint64_t* digest, const uint8_t *in, uint64_t inlen, const uint8_t* key)
	{
	_siphash((uint8_t*)digest, in, inlen, key);
	}

#endif
