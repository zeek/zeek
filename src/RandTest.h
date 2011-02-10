#include <math.h>

#define log2of10 3.32192809488736234787
/*  RT_LOG2  --  Calculate log to the base 2  */
static double rt_log2(double x)
{
    return log2of10 * log10(x);
}

#define RT_MONTEN 6  /* Bytes used as Monte Carlo
                        co-ordinates. This should be no more
                        bits than the mantissa of your "double"
                        floating point type. */

// RT_INCIRC = pow(pow(256.0, (double) (RT_MONTEN / 2)) - 1, 2.0);
#define RT_INCIRC 281474943156225.0

class RandTest {
	public:
		RandTest();
		void add(void *buf, int bufl);
		void end(double *r_ent, double *r_chisq, double *r_mean,
		         double *r_montepicalc, double *r_scc);

	private:
		long ccount[256];  /* Bins to count occurrences of values */
		long totalc;       /* Total bytes counted */
		int mp;
		int sccfirst;
		unsigned int monte[RT_MONTEN];
		long inmont, mcount;
		double cexp, montex, montey, montepi,
		       sccu0, scclast, scct1, scct2, scct3;
	};
