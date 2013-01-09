#ifndef RANDTEST_H
#define RANDTEST_H

#include "util.h"

#define RT_MONTEN 6  /* Bytes used as Monte Carlo
                        co-ordinates. This should be no more
                        bits than the mantissa of your "double"
                        floating point type. */
class EntropyVal;


class RandTest {
	public:
		RandTest();
		void add(const void* buf, int bufl);
		void end(double* r_ent, double* r_chisq, double* r_mean,
		         double* r_montepicalc, double* r_scc);

	private:
	  friend class EntropyVal;

		int64 ccount[256];  /* Bins to count occurrences of values */
		int64 totalc;       /* Total bytes counted */
		int mp;
		int sccfirst;
		unsigned int monte[RT_MONTEN];
		int64 inmont, mcount;
		double cexp, montex, montey, montepi,
		       sccu0, scclast, scct1, scct2, scct3;
};

#endif
