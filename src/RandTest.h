#include <math.h>

class EntropyVal;

#define RT_MONTEN 6  /* Bytes used as Monte Carlo
                        co-ordinates. This should be no more
                        bits than the mantissa of your "double"
                        floating point type. */

class RandTest {
	public:
		RandTest();
		void add(const void* buf, int bufl);
		void end(double* r_ent, double* r_chisq, double* r_mean,
		         double* r_montepicalc, double* r_scc);

	private:
	  friend class EntropyVal;

		long ccount[256];  /* Bins to count occurrences of values */
		long totalc;       /* Total bytes counted */
		int mp;
		int sccfirst;
		unsigned int monte[RT_MONTEN];
		long inmont, mcount;
		double cexp, montex, montey, montepi,
		       sccu0, scclast, scct1, scct2, scct3;
	};
