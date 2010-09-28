/* -*-  Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */
// $Id: TwoWise.cc 1386 2005-09-14 21:42:13Z vern $
//
// Implementation of 2-wise independent hash functions.  Contributed
// by Yin Zhang.
//

#include <stdlib.h>

#include "TwoWise.h"

TwoWise::TwoWise(int arg_dim)
	{
	dim = arg_dim;
	int n = dim > 2 ? dim : 2;

	a = new uint64[n];
	b = new uint64[n];
	c = new uint32[n];

	for ( int i = 0; i < n; ++i )
		{
		a[i] = rand64bit() & ~(1ULL);
		b[i] = rand64bit() & ~(1ULL);
		c[i] = 0;
		}

	a0 = a[0];
	b0 = b[0];
	a1 = a[1];
	b1 = b[1];
	}

TwoWise::~TwoWise()
	{
	delete[] a;
	delete[] b;
	delete[] c;
	}

void TwoWise::TestSpeed(uint32 N)
	{
	uint32 x = 0, i;

	double start_time = current_time();
	for ( i = 0; i < N; ++i )
		x ^= Hash(i);
	double end_time = current_time();
	double time0 = end_time - start_time;

	start_time = current_time();
	for ( i = 0; i < N; ++i )
		x ^= Hash(i, i);
	end_time = current_time();
	double time1 = end_time - start_time;

	fprintf(stderr, "time0=%.6f time1=%.6f x=%u\n",
		time0, time1, x);
	}
