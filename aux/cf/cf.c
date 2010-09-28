/*
 * Copyright (c) 1991, 1994, 1995, 1996, 1998, 1999, 2001, 2004
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef lint
static const char copyright[] =
    "@(#) Copyright (c) 1991, 1994, 1995, 1996, 1998, 1999, 2001, 2004\n\
The Regents of the University of California.  All rights reserved.\n";
static const char rcsid[] =
    "@(#) $Id: cf.c 5857 2008-06-26 23:00:03Z vern $ (LBL)";
#endif

#include <sys/types.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static char *argv0;

extern char *optarg;
extern int optind, opterr;

int preserve = 0;
int strict = 0;
int utc = 0;
char *sfmt = "%b %e %H:%M:%S";
char *lfmt = "%b %e %H:%M:%S %Y";
char *fmt;

/* Forwards */
int main(int, char **);
void doone(FILE *, FILE *);
void usage(void);

int
main(argc, argv)
	int argc;
	char **argv;
{
	register char *cp;
	register int status, didany, op;
	FILE *f;
	int targc;
	char **targv;

	if ((cp = strrchr(argv[0], '/')) != NULL)
		argv0 = cp + 1;
	else
		argv0 = argv[0];

	/* Set default format */
	if ((fmt = getenv("CFTIMEFMT")) == NULL)
		fmt = sfmt;

	opterr = 0;
	while ((op = getopt(argc, argv, "f:lpsu")) != EOF)
		switch (op) {

		case 'f':
			if (*optarg == '\0')
				fmt = sfmt;
			else
				fmt = optarg;
			break;

		case 'l':
			fmt = lfmt;
			break;

		case 'p':
			++preserve;
			break;

		case 's':
			++strict;
			break;

		case 'u':
			++utc;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	targc = argc - optind;
	targv = &argv[optind];

	status = 0;
	didany = 0;
	while (targc > 0) {
		f = fopen(*targv, "r");
		if (f) {
			doone(f, stdout);
			(void) fclose(f);
		} else {
			(void) fprintf(stderr, "%s: fopen: ", argv0);
			perror(*targv);
			status |= 1;
		}
		--targc;
		++targv;
		++didany;
	}
	if (!didany)
		doone(stdin, stdout);
	exit(status);
}

void
doone(fin, fout)
	FILE *fin, *fout;
{
	time_t ts;
	register char *bp, *dotbp;
	register struct tm *tp;
	register int dot_count;
	char buf[1024];
	char tstr[128] = "";
	static time_t lastts = 0;

	while (fgets(buf, sizeof(buf), fin)) {
		bp = buf;
		dotbp = NULL;
		if (isdigit(*bp)) {
			ts = atol(bp);
			++bp;
			dot_count = 0;
			while (isdigit(*bp) || *bp == '.') {
				if (*bp == '.') {
					dotbp = bp;
					++dot_count;
				}
				++bp;
			}
			if (strict && (bp - buf < 9 || dot_count > 1 ||
			    (bp - buf > 10 && dot_count != 1))) {
				/* Doesn't look like a genuine timestamp -
				 * skip it.
				 */
				fputs(buf, fout);
				continue;
			}
			if (lastts != ts) {
				if (!utc)
					tp = localtime(&ts);
				else
					tp = gmtime(&ts);
				(void)strftime(tstr, sizeof(tstr), fmt, tp);
				lastts = ts;
			}
			fputs(tstr, fout);
			if (preserve && dotbp != NULL)
				bp = dotbp;
		}
		fputs(bp, fout);
	}
}

void
usage()
{
	extern char version[];

	(void)fprintf(stderr, "%s version %s\n", argv0, version);
	(void)fprintf(stderr, "usage: %s [-f fmt] [-lpsu] [file ...]\n", argv0);
	exit(1);
}
