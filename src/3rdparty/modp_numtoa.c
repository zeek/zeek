/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil; tab-width: 4 -*- */
/* vi: set expandtab shiftwidth=4 tabstop=4: */

#include "modp_numtoa.h"

#include <stdint.h>
#include <stdio.h>
#include <math.h>
#include <limits.h>
#include <float.h>

// other interesting references on num to string convesion
// http://www.jb.man.ac.uk/~slowe/cpp/itoa.html
// and http://www.ddj.com/dept/cpp/184401596?pgno=6

// Version 19-Nov-2007
// Fixed round-to-even rules to match printf
//   thanks to Johannes Otepka

/**
 * Powers of 10
 * 10^0 to 10^9
 */
static const double _pow10[] = {1, 10, 100, 1000, 10000, 100000, 1000000,
                               10000000, 100000000, 1000000000};
static const double _pow10r[] = {1, .1, .01, .001, .0001, .00001, .000001,
                                .0000001, .00000001, .000000001};

static void strreverse(char* begin, char* end)
{
    char aux;
    while (end > begin)
        aux = *end, *end-- = *begin, *begin++ = aux;
}

// Expects 'str' to have been made using "%e" scientific notation format string
// Returns the number of characters removed
static size_t sn_strip_trailing_zeros(char* str)
	{
	char* frac = 0;

	for ( ; ; )
		{
		if ( *str == '.' )
			{
			frac = str + 1;
			break;
			}

		if ( *str == 0 )
			break;

		++str;
		}

	if ( ! frac )
		return 0;

	char* start_dec = frac;
	char* exp = 0;
	char* trailing_zeros = 0;

	for ( ; ; )
		{
		if ( *frac == 0 )
			break;

		if ( *frac == 'e' )
			{
			exp = frac;
			break;
			}

		if ( *frac == '0' )
			{
			if ( ! trailing_zeros )
				trailing_zeros = frac;
			}
		else
			trailing_zeros = 0;

		++frac;
		}

	if ( trailing_zeros == start_dec )
		--trailing_zeros;

	if ( ! trailing_zeros || ! exp )
		return 0;

	char* start_exp = exp;

	for ( ; ; )
		{
		*trailing_zeros = *exp;

		if ( *exp == 0 )
			break;

		++trailing_zeros;
		++exp;
		}

	return exp - start_exp;
	}

size_t modp_itoa10(int32_t value, char* str)
{
    char* wstr=str;
    // Take care of sign
    unsigned int uvalue = (value < 0) ? -value : value;
    // Conversion. Number is reversed.
    do *wstr++ = (char)(48 + (uvalue % 10)); while(uvalue /= 10);
    if (value < 0) *wstr++ = '-';
    *wstr='\0';

    // Reverse string
    strreverse(str,wstr-1);
    return wstr - str;
}

size_t modp_uitoa10(uint32_t value, char* str)
{
    char* wstr=str;
    // Conversion. Number is reversed.
    do *wstr++ = (char)(48 + (value % 10)); while (value /= 10);
    *wstr='\0';
    // Reverse string
    strreverse(str, wstr-1);
    return wstr - str;
}

size_t modp_litoa10(int64_t value, char* str)
{
    char* wstr=str;
    uint64_t uvalue = (value < 0) ? (value == INT64_MIN ? (uint64_t)(INT64_MAX) + 1 : -value) : value;

    // Conversion. Number is reversed.
    do *wstr++ = (char)(48 + (uvalue % 10)); while(uvalue /= 10);
    if (value < 0) *wstr++ = '-';
    *wstr='\0';

    // Reverse string
    strreverse(str,wstr-1);
    return wstr - str;
}

size_t modp_ulitoa10(uint64_t value, char* str)
{
    char* wstr=str;
    // Conversion. Number is reversed.
    do *wstr++ = (char)(48 + (value % 10)); while (value /= 10);
    *wstr='\0';
    // Reverse string
    strreverse(str, wstr-1);
    return wstr - str;
}

size_t modp_dtoa(double value, char* str, int prec)
{
    /* Hacky test for NaN
     * under -fast-math this won't work, but then you also won't
     * have correct nan values anyways.  The alternative is
     * to link with libmath (bad) or hack IEEE double bits (bad)
     */
    if (! (value == value)) {
        str[0] = 'n'; str[1] = 'a'; str[2] = 'n'; str[3] = '\0';
        return 3;
    }

    /* we'll work in positive values and deal with the
       negative sign issue later */
    int neg = 0;
    if (value < 0) {
        neg = 1;
        value = -value;
    }

    /* if input is larger than thres_max, revert to exponential */
    const double thres_max = (double)(INT_MAX);

    /* for very large numbers switch back to native sprintf for exponentials.
       anyone want to write code to replace this? */
    /*
      normal printf behavior is to print EVERY whole number digit
      which can be 100s of characters overflowing your buffers == bad
    */
    if (value >= thres_max) {
        int n = sprintf(str, "%.*e", DBL_DECIMAL_DIG - 1, neg ? -value : value);
        n -= sn_strip_trailing_zeros(str);
        return n;
    }

    double diff = 0.0;
    char* wstr = str;

    if (prec < 0) {
        prec = 0;
    } else if (prec > 9) {
        /* precision of >= 10 can lead to overflow errors */
        prec = 9;
    }

    int whole = (int) value;
    double tmp = (value - whole) * _pow10[prec];
    uint32_t frac = (uint32_t)(tmp);
    diff = tmp - frac;

    if (diff > 0.5) {
        ++frac;
        /* handle rollover, e.g.  case 0.99 with prec 1 is 1.0  */
        if (frac >= _pow10[prec]) {
            frac = 0;
            ++whole;
        }
    } else if (diff == 0.5 && ((frac == 0) || (frac & 1))) {
        /* if halfway, round up if odd, OR
           if last digit is 0.  That last part is strange */
        ++frac;
    }

    if (prec == 0) {
        diff = value - whole;
        if (diff > 0.5) {
            /* greater than 0.5, round up, e.g. 1.6 -> 2 */
            ++whole;
        } else if (diff == 0.5 && (whole & 1)) {
            /* exactly 0.5 and ODD, then round up */
            /* 1.5 -> 2, but 2.5 -> 2 */
            ++whole;
        }
    } else {
        int count = prec;
        // now do fractional part, as an unsigned number
        do {
            --count;
            *wstr++ = (char)(48 + (frac % 10));
        } while (frac /= 10);
        // add extra 0s
        while (count-- > 0) *wstr++ = '0';
        // add decimal
        *wstr++ = '.';
    }

    // do whole part
    // Take care of sign
    // Conversion. Number is reversed.
    do *wstr++ = (char)(48 + (whole % 10)); while (whole /= 10);
    if (neg) {
        *wstr++ = '-';
    }
    *wstr='\0';
    strreverse(str, wstr-1);
    return wstr - str;
}


// This is near identical to modp_dtoa above
//   The differnce is noted below
size_t modp_dtoa2(double value, char* str, int prec)
{
    /* Hacky test for NaN
     * under -fast-math this won't work, but then you also won't
     * have correct nan values anyways.  The alternative is
     * to link with libmath (bad) or hack IEEE double bits (bad)
     */
    if (! (value == value)) {
        str[0] = 'n'; str[1] = 'a'; str[2] = 'n'; str[3] = '\0';
        return 3;
    }

    /* we'll work in positive values and deal with the
       negative sign issue later */
    int neg = 0;
    if (value < 0) {
        neg = 1;
        value = -value;
    }

    /* if input is larger than thres_max, revert to exponential */
    const double thres_max = (double)(INT_MAX);

    /* for very large numbers switch back to native sprintf for exponentials.
       anyone want to write code to replace this? */
    /*
      normal printf behavior is to print EVERY whole number digit
      which can be 100s of characters overflowing your buffers == bad
    */
    if (value >= thres_max) {
        int n = sprintf(str, "%.*e", DBL_DECIMAL_DIG - 1, neg ? -value : value);
        n -= sn_strip_trailing_zeros(str);
        return n;
    }

    int count;
    double diff = 0.0;
    char* wstr = str;

    if (prec < 0) {
        prec = 0;
    } else if (prec > 9) {
        /* precision of >= 10 can lead to overflow errors */
        prec = 9;
    }

    double smallest = _pow10r[prec];

    if (value != 0.0 && value < smallest) {
        int n = sprintf(str, "%.*e", DBL_DECIMAL_DIG - 1, neg ? -value : value);
        n -= sn_strip_trailing_zeros(str);
        return n;
    }

    int whole = (int) value;
    double tmp = (value - whole) * _pow10[prec];
    uint32_t frac = (uint32_t)(tmp);
    diff = tmp - frac;

    if (diff > 0.5) {
        ++frac;
        /* handle rollover, e.g.  case 0.99 with prec 1 is 1.0  */
        if (frac >= _pow10[prec]) {
            frac = 0;
            ++whole;
        }
    } else if (diff == 0.5 && ((frac == 0) || (frac & 1))) {
        /* if halfway, round up if odd, OR
           if last digit is 0.  That last part is strange */
        ++frac;
    }

    if (prec == 0) {
        diff = value - whole;
        if (diff > 0.5) {
            /* greater than 0.5, round up, e.g. 1.6 -> 2 */
            ++whole;
        } else if (diff == 0.5 && (whole & 1)) {
            /* exactly 0.5 and ODD, then round up */
            /* 1.5 -> 2, but 2.5 -> 2 */
            ++whole;
        }

        //vvvvvvvvvvvvvvvvvvv  Diff from modp_dto2
    } else if (frac) {
        count = prec;
        // now do fractional part, as an unsigned number
        // we know it is not 0 but we can have leading zeros, these
        // should be removed
        while (!(frac % 10)) {
            --count;
            frac /= 10;
        }
        //^^^^^^^^^^^^^^^^^^^  Diff from modp_dto2

        // now do fractional part, as an unsigned number
        do {
            --count;
            *wstr++ = (char)(48 + (frac % 10));
        } while (frac /= 10);
        // add extra 0s
        while (count-- > 0) *wstr++ = '0';
        // add decimal
        *wstr++ = '.';
    }

    // do whole part
    // Take care of sign
    // Conversion. Number is reversed.
    do *wstr++ = (char)(48 + (whole % 10)); while (whole /= 10);
    if (neg) {
        *wstr++ = '-';
    }
    *wstr='\0';
    strreverse(str, wstr-1);
    return wstr - str;
}

// This is near identical to modp_dtoa2 above, excep that it never uses
// exponential notation and requires a buffer length.
size_t modp_dtoa3(double value, char* str, int n, int prec)
{
    /* Hacky test for NaN
     * under -fast-math this won't work, but then you also won't
     * have correct nan values anyways.  The alternative is
     * to link with libmath (bad) or hack IEEE double bits (bad)
     */
    if (! (value == value)) {
        str[0] = 'n'; str[1] = 'a'; str[2] = 'n'; str[3] = '\0';
        return 3;
    }

    /* we'll work in positive values and deal with the
       negative sign issue later */
    int neg = 0;
    if (value < 0) {
        neg = 1;
        value = -value;
    }

    if (prec < 0) {
        prec = 0;
    } else if (prec > 9) {
        /* precision of >= 10 can lead to overflow errors */
        prec = 9;
    }

    /* if input is larger than thres_max, revert to exponential */
    const double thres_max = (double)(INT_MAX);

    /* for very large numbers switch back to native sprintf for exponentials.
       anyone want to write code to replace this? */
    /*
      normal printf behavior is to print EVERY whole number digit
      which can be 100s of characters overflowing your buffers == bad
    */
    if (value >= thres_max) {
        /* ---- Modified part, compared to modp_dtoa3. */
        int i = snprintf(str, n, "%.*f", prec, neg ? -value : value);

        if ( i < 0 || i >= n ) {
        // Error or truncated output.
            snprintf(str, n, "NAN");
            return 3;
            }

        /* Remove trailing zeros. */

        char* p;
        for ( p = str + i - 1; p >= str && *p == '0'; --p );

        if ( p >= str && *p == '.' )
            --p;

        *++p = '\0';
        return p - str - 1;

        /* ---- End of modified part.. */
    }

    int count;
    double diff = 0.0;
    char* wstr = str;

    int whole = (int) value;
    double tmp = (value - whole) * _pow10[prec];
    uint32_t frac = (uint32_t)(tmp);
    diff = tmp - frac;

    if (diff > 0.5) {
        ++frac;
        /* handle rollover, e.g.  case 0.99 with prec 1 is 1.0  */
        if (frac >= _pow10[prec]) {
            frac = 0;
            ++whole;
        }
    } else if (diff == 0.5 && ((frac == 0) || (frac & 1))) {
        /* if halfway, round up if odd, OR
           if last digit is 0.  That last part is strange */
        ++frac;
    }

    if (prec == 0) {
        diff = value - whole;
        if (diff > 0.5) {
            /* greater than 0.5, round up, e.g. 1.6 -> 2 */
            ++whole;
        } else if (diff == 0.5 && (whole & 1)) {
            /* exactly 0.5 and ODD, then round up */
            /* 1.5 -> 2, but 2.5 -> 2 */
            ++whole;
        }

        //vvvvvvvvvvvvvvvvvvv  Diff from modp_dto2
    } else if (frac) {
        count = prec;
        // now do fractional part, as an unsigned number
        // we know it is not 0 but we can have leading zeros, these
        // should be removed
        while (!(frac % 10)) {
            --count;
            frac /= 10;
        }
        //^^^^^^^^^^^^^^^^^^^  Diff from modp_dto2

        // now do fractional part, as an unsigned number
        do {
            --count;
            *wstr++ = (char)(48 + (frac % 10));
        } while (frac /= 10);
        // add extra 0s
        while (count-- > 0) *wstr++ = '0';
        // add decimal
        *wstr++ = '.';
    }

    // do whole part
    // Take care of sign
    // Conversion. Number is reversed.
    do *wstr++ = (char)(48 + (whole % 10)); while (whole /= 10);
    if (neg) {
        *wstr++ = '-';
    }
    *wstr='\0';
    strreverse(str, wstr-1);
    return wstr - str;
}
