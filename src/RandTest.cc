/*
	Apply various randomness tests to a stream of bytes

		by John Walker  --  September 1996
			http://www.fourmilab.ch/random

		This software is in the public domain. Permission to use, copy, modify,
		and distribute this software and its documentation for any purpose and
		without fee is hereby granted, without any conditions or restrictions.
		This software is provided “as is” without express or implied warranty.

	Modified for Bro by Seth Hall - July 2010
*/

#include <math.h>
#include "RandTest.h"

#define log2of10 3.32192809488736234787
/*  RT_LOG2  --  Calculate log to the base 2  */
static double rt_log2(double x)
{
    return log2of10 * log10(x);
}

// RT_INCIRC = pow(pow(256.0, (double) (RT_MONTEN / 2)) - 1, 2.0);
#define RT_INCIRC 281474943156225.0

RandTest::RandTest()
	{
	totalc = 0;
	mp = 0;
	sccfirst = 1;
	inmont = mcount = 0;
	cexp = montex = montey = montepi = sccu0 = scclast = scct1 = scct2 = scct3 = 0.0;

	for (int i = 0; i < 256; i++)
		{
		ccount[i] = 0;
		}
	}

void RandTest::add(const void *buf, int bufl)
	{
	const unsigned char *bp = static_cast<const unsigned char*>(buf);
	int oc;

	while (bufl-- > 0)
		{
		oc = *bp++;
		ccount[oc]++;   /* Update counter for this bin */
		totalc++;

		/* Update inside / outside circle counts for Monte Carlo
 		   computation of PI */
		monte[mp++] = oc;  /* Save character for Monte Carlo */
		if (mp >= RT_MONTEN)  /* Calculate every RT_MONTEN character */
			{
			mp = 0;
			mcount++;
			montex = 0;
			montey = 0;
			for (int mj=0; mj < RT_MONTEN/2; mj++)
				{
				montex = (montex * 256.0) + monte[mj];
				montey = (montey * 256.0) + monte[(RT_MONTEN / 2) + mj];
				}
			if (montex*montex + montey*montey <= RT_INCIRC)
				{
				inmont++;
				}
			}

		/* Update calculation of serial correlation coefficient */
		if (sccfirst)
			{
			sccfirst = 0;
			scclast = 0;
			sccu0 = oc;
			}
		else
			{
			scct1 = scct1 + scclast * oc;
			}

		scct2 = scct2 + oc;
		scct3 = scct3 + (oc * oc);
		scclast = oc;
		oc <<= 1;
		}
	}

void RandTest::end(double* r_ent, double* r_chisq,
                   double* r_mean, double* r_montepicalc, double* r_scc)
	{
	int i;
	double ent, chisq, scc, datasum;
	ent = 0.0; chisq = 0.0; scc = 0.0; datasum = 0.0;
	double prob[256];    /* Probabilities per bin for entropy */

	/* Complete calculation of serial correlation coefficient */
	scct1 = scct1 + scclast * sccu0;
	scct2 = scct2 * scct2;
	scc = totalc * scct3 - scct2;
	if (scc == 0.0)
	   scc = -100000;
	else
	   scc = (totalc * scct1 - scct2) / scc;

	/* Scan bins and calculate probability for each bin and
	   Chi-Square distribution.  The probability will be reused
	   in the entropy calculation below.  While we're at it,
	   we sum of all the data which will be used to compute the
	   mean. */
	cexp = totalc / 256.0;  /* Expected count per bin */
	for (i = 0; i < 256; i++)
		{
		double a = ccount[i] - cexp;

		prob[i] = ((double) ccount[i]) / totalc;
		chisq += (a * a) / cexp;
		datasum += ((double) i) * ccount[i];
		}

	/* Calculate entropy */
	for (i = 0; i < 256; i++)
		{
		if (prob[i] > 0.0)
			{
			ent += prob[i] * rt_log2(1 / prob[i]);
			}
		}

	/* Calculate Monte Carlo value for PI from percentage of hits
	   within the circle */
	montepi = 4.0 * (((double) inmont) / mcount);

	/* Return results through arguments */
	*r_ent = ent;
	*r_chisq = chisq;
	*r_mean = datasum / totalc;
	*r_montepicalc = montepi;
	*r_scc = scc;
	}
