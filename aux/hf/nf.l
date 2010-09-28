N              [0-9]
O              ({N}{1,3})

    #include <sys/types.h>
    #include <sys/socket.h>

    #include <netinet/in.h>

    #include <arpa/inet.h>
    #include <arpa/nameser.h>

    #include <ctype.h>
    #ifdef HAVE_MEMORY_H
    #include <memory.h>
    #endif
    #include <netdb.h>
    #include <resolv.h>
    #include <stdio.h>
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
    char *addr2host(char *);
    void convert(char *);
    int pad;

%%

{O}\.{O}\.{O}\.{O}	convert(yytext);
{O}\.{O}\.{O}		if (pad) {
				char buf[256];
				strcpy(buf, yytext);
				strcat(buf, ".0");
				convert(buf);
			} else {
				ECHO;
			}
{O}\.{O}		if (pad) {
				char buf[256];
				strcpy(buf, yytext);
				strcat(buf, ".0.0");
				convert(buf);
			} else {
				ECHO;
			}
{O}			if (pad) {
				char buf[256];
				strcpy(buf, yytext);
				strcat(buf, ".0.0.0");
				convert(buf);
			} else {
				ECHO;
			}

{N}+			ECHO;
[^0-9\n]+		ECHO;
[^0-9\n]+\n		ECHO;

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
    "@(#) $Id: nf.l 909 2004-12-09 04:27:10Z jason $ (LBL)";
#endif

#define HSIZE 2048		/* must be a power of two */

struct htable {
	u_int addr;
	char *name;
	struct htable *next;
} htable[HSIZE];

int lcase = 1;			/* force lowercase */
int printboth = 0;
#ifdef DEBUG
int debug = 0;
#endif

int targc;
char **targv;

extern char *optarg;
extern int optind, opterr;

/* Forwards */
int main(int, char **);
#ifdef DEBUG
void dump(void);
#endif

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
	while ((op = getopt(argc, argv, "dibp")) != EOF)
		switch (op) {

#ifdef DEBUG
		case 'd':
			++debug;
			break;
#endif

		case 'i':
			lcase = 0;
			break;

		case 'p':
			pad = 1;
			break;

		case 'b':
			printboth = 1;
			break;

		default:
			(void)fprintf(stderr, "usage: %s [-dibp] [file ...]\n",
			    argv0);
			exit(1);
			/* NOTREACHED */
		}

	setnetent(1);

	/* Let yywrap() figure out if there are any arguments to open */
	targc = argc - optind;
	targv = &argv[optind];
	yyin = 0;
	(void)yywrap();

	/* Process file opened by yywrap() or stdin if no arguments */
	if (yyin)
		yylex();

#ifdef DEBUG
	if (debug) {
		fflush(stdout);
		dump();
	}
#endif
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

void
convert(str)
	char *str;
{
	fputs(addr2host(str), stdout);
	if (printboth) {
		putchar('(');
		fputs(str, stdout);
		putchar(')');
	}
}

char *
addr2host(str)
	char *str;
{
	register u_long addr, net;
	register char *cp, *host;
	register struct netent *hp;
	register struct htable *p, *p2;
	struct in_addr ia;

	addr = inet_addr(str);

	/* First check if we already know about it */
	for (p = &htable[addr & (HSIZE - 1)]; p; p = p->next)
		if (p->addr == addr && p->name)
			return(p->name);

	/* Try to lookup this net */
	ia.s_addr = addr;
	net = inet_netof(ia);
	if ((hp = getnetbyaddr(net, AF_INET)) != NULL)
		host = hp->n_name;
	else
		host = inet_ntoa(ia);

	if (lcase)
		for (cp = host; *cp; ++cp)
			if (isupper(*cp))
				*cp = tolower(*cp);

	/* Malloc space for new hostname */
	cp = malloc((u_int) strlen(host) + 1);
	if (cp == 0)
		return(host);

	/* Find slot in hash table */
	p = &htable[addr & (HSIZE - 1)];
	if (p->name) {
		/* Handle the collision */
		p2 = (struct htable *)malloc(sizeof(struct htable));
		if (p2 == 0) {
			/* Lose, lose */
			free(cp);
			return(host);
		}
		memset((char *)p2, 0, sizeof(struct htable));
		p2->next = p->next;
		p->next = p2;
		p = p2;
	}

	/* Install new host */
	p->addr = addr;
	p->name = strcpy(cp, host);

	/* Return answer */
	return(p->name);
}

#ifdef DEBUG
void
dump()
{
	register int i, j, n, d;
	register struct htable *p, *p2;

	d = n = 0;
	for (p = htable, i = 0; i < HSIZE; ++p, ++i)
		if (p->name) {
			++n;
			j = 0;
			for (p2 = p; p2; p2 = p2->next) {
				(void)fprintf(stderr,
				    "%4d:%d 0x%08x \"%s\"\n", i, j,
				    p2->addr, p2->name ? p2->name : "<nil>");
				++d;
				++j;
			}
		}
	d -= n;
	(void)fprintf(stderr, "%d entries (%d dynamically linked)\n", n, d);
}
#endif
