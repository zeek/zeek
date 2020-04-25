#pragma once

#include <stdint.h>

#define SIPHASH_KEYLEN 16

extern "C" {
	uint64_t siphash24(const void* src, unsigned long src_sz, const uint64_t* key);
}

// [Bro] Wrapper for better type-safety.
inline void siphash(uint64_t* digest, const uint8_t* in, uint64_t inlen, const uint8_t* key)
	{
	*digest = siphash24(in, inlen, (const uint64_t*)key);
	}
