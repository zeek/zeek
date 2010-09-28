N              [0-9]

    #include <sys/types.h>

    #include <netdb.h>
    #include <string.h>
    #include <unistd.h>

    #include "gnuc.h"
    #ifdef HAVE_OS_PROTO_H
    #include "os-proto.h"
    #endif

    #undef yywrap
    #ifdef FLEX_SCANNER
    #define YY_NO_UNPUT
    #endif
    int yywrap(void);
    int yylex(void);
    void convert(char *);

%%

"["{N}+"]"		convert(yytext);
[^0-9[\]\n]+\n?		ECHO;
.|\n			ECHO;

%%

/*
 * Copyright (c) 1990, 1991, 1996, 1999, 2000, 2004
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
    "@(#) Copyright (c) 1990, 1991, 1996, 1999, 2000, 2004\n\
The Regents of the University of California.  All rights reserved.\n";
static const char rcsid[] =
    "@(#) $Id: pf.l 909 2004-12-09 04:27:10Z jason $ (LBL)";
#endif

#ifdef DEBUG
int debug = 0;
#endif

#define MAX_PORT_NUM 65535
char *port_to_name[MAX_PORT_NUM+1];

int targc;
char **targv;

extern char *optarg;
extern int optind, opterr;

/* Forwards */
int main(int, char **);
char *dup_string(char *);
void portinit(void);

int
main(argc, argv)
	int argc;
	char **argv;
{
	register char *cp;
	register int op;
	char *argv0;

	if ((cp = strrchr(argv[0], '/')) != NULL)
		argv0 = cp + 1;
	else
		argv0 = argv[0];

	opterr = 0;
	while ((op = getopt(argc, argv, "d")) != EOF)
		switch (op) {

#ifdef DEBUG
		case 'd':
			++debug;
			break;
#endif

		default:
			(void)fprintf(stderr, "usage: %s [-d] [file ...]\n",
			    argv0);
			exit(1);
			/* NOTREACHED */
		}

	/* Let yywrap() figure out if there are any arguments to open */
	targc = argc - optind;
	targv = &argv[optind];
	yyin = 0;
	(void)yywrap();

	portinit();

	/* Process file opened by yywrap() or stdin if no arguments */
	if (yyin)
		yylex();

#ifdef DEBUG
	if (debug) {
		register int i;
		for (i=0; i <= MAX_PORT_NUM; ++i)
			if (port_to_name[i])
				fprintf(stderr, "[%d]\t%s\n", i,
				    port_to_name[i]);
	}
#endif	/* DEBUG */
	exit(0);
}

int
yywrap()
{
	register char *file;
	static int didany = 0;

	/* Close file, if necessary */
	if (yyin && yyin != stdin) {
		(void)fclose(yyin);
		yyin = 0;
	}

	/* Spin through arguments until we run out or successfully open one */
	while (targc > 0) {
		file = targv[0];
		--targc;
		++targv;
		++didany;
		if ((yyin = fopen(file, "r")) != NULL)
			return(0);
		else
			perror(file);
	}
	if (!didany)
		yyin = stdin;
	return(1);
}

char *
dup_string(src)
	char *src;
{
	char *dst;

	dst = malloc(strlen(src)+1);
	if (dst)
		strcpy(dst, src);
	return dst;
}

void
convert(str)
	char *str;
{
	register int port;

	port = atoi(str+1);
	if (port >= 0 && port <= MAX_PORT_NUM && port_to_name[port] != 0)
		str = port_to_name[port];
	fputs(str, stdout);
}

void
portinit()
{
	struct servent *sp;

	while ((sp = getservent()) != 0) {
		if (port_to_name[sp->s_port] == 0 ||
		    sp->s_proto[0] == 't')
			port_to_name[sp->s_port] = dup_string(sp->s_name);
	}
	endservent();

}
