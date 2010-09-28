/* -*-  Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */
// $Id: TwoWise.h 2809 2006-04-23 20:26:07Z vern $
//
// Implementation of 2-wise independent hash functions.  Contributed
// by Yin Zhang.
//

#ifndef twowise_h
#define twowise_h

#include "util.h"

typedef union {
	uint64 as_int64;
	uint32 as_int32s[2];
	uint32 as_int16s[4];
} int64views;

#ifdef WORDS_BIGENDIAN
#define TOP32BITS(h) h.as_int32s[0]
#else
#define TOP32BITS(h) h.as_int32s[1]
#endif

typedef union {
	uint32 as_int32;
	uint16 as_int16s[2];
	uint16 as_int8s[4];
} int32views;

class TwoWise {
public:
	TwoWise(int dim = 0);
	~TwoWise();

	uint32 Hash(uint32 k) const
		{
		int64views h;
		h.as_int64 = a0*k + b0;
		return TOP32BITS(h);
		}

	uint32 Hash(uint32 k0, uint32 k1) const
		{
		int64views h;
		h.as_int64 = (a0*k0+b0) ^ (a1*k1+b1);
		return TOP32BITS(h);
		}

	uint32 Hash(const uint32* k) const
		{
		int64views h;
		h.as_int64 = (a0*k[0]+b0);

		for ( int i = 1; i < dim; ++i )
			h.as_int64 ^= (a[i]*k[i] + b[i]);

		return TOP32BITS(h);
		}

	uint32 Hash(int size, const uint8* data) const
		{
		if ( size == 0 )
			return 0;

		// Copy data to c to resolve any potential alignment problem.
		int num_words = (size + 3) >> 2;
		c[num_words - 1] = 0;	// pad with 0
		memcpy(c, data, size);

		int64views h;
		h.as_int64 = (a0*c[0]+b0);

		for ( int i = 1; i < num_words; ++i )
			h.as_int64 ^= (a[i]*c[i] + b[i]);

		return TOP32BITS(h);
		}

	void TestSpeed(uint32 N = 1000000);

private:

	// Coefficients in Dietzfelbinger scheme.
	uint64 a0, b0, a1, b1;	// for 1-d and 2-d case
	uint64 *a, *b;		// for N-d case
	uint32 *c;

	int dim;
};

#endif // twowise_h
