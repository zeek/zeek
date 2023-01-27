#pragma once

#include "zeek/zeek-config.h"

#include <cstdint>

#define RT_MONTEN                                                                                  \
	6 /* Bytes used as Monte Carlo                                                                 \
	     co-ordinates. This should be no more                                                      \
	     bits than the mantissa of your "double"                                                   \
	     floating point type. */

namespace zeek
	{

class EntropyVal;

namespace detail
	{

class RandTest
	{
public:
	RandTest();
	void add(const void* buf, int bufl);
	void end(double* r_ent, double* r_chisq, double* r_mean, double* r_montepicalc, double* r_scc);

private:
	friend class zeek::EntropyVal;

	int64_t ccount[256]; /* Bins to count occurrences of values */
	int64_t totalc; /* Total bytes counted */
	int mp;
	int sccfirst;
	unsigned int monte[RT_MONTEN] = {0};
	int64_t inmont, mcount;
	double cexp, montex, montey, montepi, sccu0, scclast, scct1, scct2, scct3;
	};

	} // namespace detail
	} // namespace zeek
