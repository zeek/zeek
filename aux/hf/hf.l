N              [0-9]
O              ({N}{1,3})

C              [0-9A-Fa-f]
H              ({C}{1,4})

    #include "config.h"
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/time.h>
    #include <sys/stat.h>

    #include <netinet/in.h>

    #include <arpa/inet.h>

    #ifdef NEED_NAMESER_COMPAT_H
        #include <arpa/nameser_compat.h>
    #else
        #include <arpa/nameser.h>
    #endif

    #ifndef NS_MAXDNAME
	    #define NS_MAXDNAME 1025
    #endif
    #ifndef NS_INADDRSZ
	    #define NS_INADDRSZ 4
    #endif
    #ifndef NS_IN6ADDRSZ
	    #define NS_IN6ADDRSZ 16
    #endif

    #include <ctype.h>
    #include <errno.h>
    #ifdef HAVE_MEMORY_H
    #include <memory.h>
    #endif
    #include <netdb.h>
    #include <resolv.h>
    #include <setjmp.h>
    #include <signal.h>
    #include <stdio.h>
    #include <string.h>
    #include <unistd.h>

    #include "gnuc.h"
    #ifdef HAVE_OS_PROTO_H
    #include "os-proto.h"
    #endif

    #include "setsignal.h"
    #include "nb_dns.h"

    #undef yywrap
    #ifdef FLEX_SCANNER
    #define YY_NO_UNPUT
    #endif
    int yywrap(void);
    int yylex(void);
    void convert(const char *, int);

    #ifdef HAVE_ASYNC_DNS
    #define ECHO \
	if (!lookup_pass) { (void) fwrite( yytext, yyleng, 1, yyout ); }
    int lookup_pass;		/* true if lookup only */
    #endif
    int linemode;		/* convert at most one entry per line */
    int triedone;

%%


::{O}(\.{O}){3}		convert(yytext, 1);
{O}(\.{O}){3}		convert(yytext, 0);

{H}(:{H}){7}		convert(yytext, 1);
{H}:(:{H}){1,6}		convert(yytext, 1);
({H}:){2}(:{H}){1,5}	convert(yytext, 1);
({H}:){3}(:{H}){1,4}	convert(yytext, 1);
({H}:){4}(:{H}){1,3}	convert(yytext, 1);
({H}:){5}(:{H}){1,2}	convert(yytext, 1);
({H}:){6}:{H}		convert(yytext, 1);

({O}\.){1,3}		ECHO;		/* anti-backtrack */
{O}((\.{O}){1,2})	ECHO;		/* anti-backtrack */

{N}+			ECHO;
[^0-9\n]+		ECHO;
[^0-9\n]+\n		{
			ECHO;
			triedone = 0;
			}

\n			{
			ECHO;
			triedone = 0;
			}

%%

/*
 * Copyright (c) 1989, 1990, 1991, 1992, 1993, 1994, 1996, 1998, 1999, 2000, 2001, 2002, 2004
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
    "@(#) Copyright (c) 1989, 1990, 1991, 1992, 1993, 1994, 1996, 1998, 1999, 2000, 2001, 2002, 2004\n\
The Regents of the University of California.  All rights reserved.\n";
static const char rcsid[] =
    "@(#) $Id: hf.l 1420 2005-09-29 22:25:14Z vern $ (LBL)";
#endif


#define HSIZE 8192		/* must be a power of two */

struct htable {
	char addr[NS_IN6ADDRSZ];
	int af;			/* address family */
	int alen;
	int state;
	char *name;		/* overloaded variable */
	struct htable *next;
} htable[HSIZE];

#define STATE_FREE	0	/* not in use */
#define STATE_RAW	1	/* couldn't translate */
#define STATE_SENTPTR	2
#define STATE_HAVEPTR	3
#define STATE_SENTA	4
#define STATE_HAVEA	5

int strip = 1;			/* strip local domain when possible */
int lcase = 1;			/* force lowercase */
int shortdomain;		/* strip entire domain */
int printboth;			/* print both addr & name */
#ifdef HAVE_ASYNC_DNS
int asyncdns;			/* 2 pass async dns hack */
int numasync;			/* number of outstanding async requests */
int asyncfd;
#endif
int networknumber;		/* convert to network numbers */
int check;			/* check PTR's against A records */
#ifdef DEBUG
int debug = 0;
#endif

int tmo;			/* seconds to wait for a answer from the dns */
int doingdns;			/* true if we're waiting for the nameserver */
jmp_buf alrmenv;		/* longjmp() buffer */

char *prog;

char domain[64];		/* current domain name (including '.') */
int domainlen;			/* length of domain name */

char azero[NS_IN6ADDRSZ];

#ifdef HAVE_ASYNC_DNS
struct nb_dns_info *nd;
#endif

int targc;
char **targv;

extern char *optarg;
extern int optind, opterr;

/* ANSI C defines this */
#ifndef __STDC__
extern char *malloc();
#endif

/* Forwards */
char *a2h(const char *, int, int);
char *addr2host(const char *, int, int);
#ifdef HAVE_ASYNC_DNS
void asyncreap(int);
#endif
struct htable *cacheaddr(const char *, int, int, int, const char *);
#ifdef DEBUG
void dump(void);
#endif
int getdomain(void);
struct htable *hash(const char *, int, int);
#ifdef HAVE_ASYNC_DNS
int ispipe(FILE *);
#endif
struct htable *lookupaddr(const char *, int, int);
int main(int, char **);
void massagename(char *);
RETSIGTYPE timeout(int);
void usage(void);

int
main(argc, argv)
	int argc;
	char **argv;
{
	register char *cp;
	register int op;
#ifdef HAVE_ASYNC_DNS
	char errstr[NB_DNS_ERRSIZE];
#endif

	if ((cp = strrchr(argv[0], '/')) != NULL)
		prog = cp + 1;
	else
		prog = argv[0];

	opterr = 0;
	while ((op = getopt(argc, argv, "1abcdilnNt:")) != EOF)
		switch (op) {

		case '1':
			++linemode;
			break;

		case 'a':
#ifdef HAVE_ASYNC_DNS
			++asyncdns;
#else
			fprintf(stderr,
			    "%s: warning: -a not supported; ignored\n", prog);
#endif
			break;

		case 'b':
			++printboth;
			break;

		case 'c':
			++check;
			break;

#ifdef DEBUG
		case 'd':
			++debug;
			break;
#endif

		case 'i':
			lcase = 0;
			break;

		case 'l':
			strip = 0;
			break;

		case 'n':
#ifdef notdef
			++networknumber;
#else
			fprintf(stderr, "%s: -n not currently impemented\n",
			    prog);
			exit(1);
#endif
			break;

		case 'N':
			++shortdomain;
			break;

		case 't':
			tmo = atoi(optarg);
			if (tmo <= 0)
				usage();
			break;

		default:
			usage();
		}

#ifdef HAVE_ASYNC_DNS
	if (asyncdns) {
		nd = nb_dns_init(errstr);
		if (nd == NULL) {
			fprintf(stderr, "%s: nb_dns_init: %s\n", prog, errstr);
			exit(1);
		}
		asyncfd = nb_dns_fd(nd);
		/* If no explicit timeout, use resolver retransmit */
		if (tmo == 0)
			tmo = _res.retrans;
	}
#endif

	/* Figure out our domain, if necessary */
	if (!strip || shortdomain || !getdomain())
		domain[0] = '\0';

	/* Up number of retries, we really want answers */
	_res.retry = 20;

	/* Don't search, we'll use only FQDNs */
	_res.options &= ~RES_DNSRCH;

	/* Setup alarm catcher if -t */
#ifdef HAVE_ASYNC_DNS
	if (!asyncdns)
#endif
		if (tmo > 0)
			(void)setsignal(SIGALRM, timeout);

	/* Let yywrap() figure out if there are any arguments to open */
	targc = argc - optind;
	targv = &argv[optind];
	yyin = NULL;
	(void)yywrap();

	/* Process file opened by yywrap() or stdin if no arguments */
	if (yyin) {
#ifdef HAVE_ASYNC_DNS
		/* XXX depends on the type of stdin */
		/* XXX can we do a test rewind? */
#ifdef notdef
		if (asyncdns && yyin == stdin)
			fprintf(stderr,
			    "%s: warning: can't use -a on stdin\n", prog);
#endif
#endif
		yylex();
	}

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
	if (yyin) {
#ifdef HAVE_ASYNC_DNS
		if (asyncdns) {
			if (lookup_pass) {
				if (fseek(yyin, 0L, SEEK_SET) < 0) {
					fprintf(stderr,
					    "%s: fseek/rewind: %s\n",
					    prog, strerror(errno));
					exit(1);
				}
				yyrestart(yyin);
				lookup_pass = 0;
				asyncreap(1);
				return (0);
			}
			numasync = 0;
		}
#endif
		if (yyin != stdin)
			(void)fclose(yyin);
		yyin = NULL;
	}

	/* Spin through arguments until we run out or successfully open one */
	while (targc > 0) {
		file = targv[0];
		--targc;
		++targv;
		++didany;
		if ((yyin = fopen(file, "r")) != NULL) {
#ifdef HAVE_ASYNC_DNS
			if (asyncdns)
				lookup_pass = 1;
#endif
			return (0);
		}
		perror(file);
	}
	if (!didany) {
		yyin = stdin;
#ifdef HAVE_ASYNC_DNS
		if (asyncdns) {
			if (ispipe(yyin)) {
				fprintf(stderr,
				    "%s: warning: can't use -a on a pipe\n",
				    prog);
				asyncdns = 0;
			} else
				lookup_pass = 1;
		}
#endif
	}
	return (1);
}

int
getdomain()
{
	register char *cp;
	register struct hostent *hp;
	char host[128];

	if (gethostname(host, sizeof(host) - 1) < 0)
		return (0);
	if ((cp = strchr(host, '.')) == NULL) {
		/* Not already canonical */
		if (tmo > 0)
			alarm(tmo);
		doingdns = 1;
		if (setjmp(alrmenv))
			return (0);
		hp = gethostbyname(host);
		doingdns = 0;
		if (hp == NULL)
			return (0);
		if ((cp = strchr(hp->h_name, '.')) == NULL)
			return (0);
	}
	(void)strncpy(domain, cp, sizeof(domain));
	domain[sizeof(domain) - 1] = '\0';
	if (lcase)
		for (cp = domain; *cp; ++cp)
			if (isupper((int)*cp))
				*cp = tolower(*cp);
	domainlen = strlen(domain);
	return (1);
}

RETSIGTYPE
timeout(int signo)
{

	if (doingdns) {
		doingdns = 0;
		longjmp(alrmenv, 1);
	}
	return RETSIGVAL;
}

/* Convert address to hostname via the dns */
char *
a2h(register const char *ap, register int alen, register int af)
{
	register char **pp;
	register size_t len;
	static struct hostent *hp;
	static char *host = NULL;
	static size_t hostlen = 0;

	/* Look up the PTR */
	if (tmo > 0)
		alarm(tmo);
	doingdns = 1;
	if (setjmp(alrmenv))
		return (NULL);
	hp = gethostbyaddr(ap, alen, af);
	doingdns = 0;
	if (hp == NULL)
		return (NULL);

	len = strlen(hp->h_name) + 1;
	if (hostlen < len) {
		if (len < 132)
			len = 132;
		if (host == NULL)
			host = malloc(len);
		else
			host = realloc(host, len);
		if (host == NULL) {
			hostlen = 0;
			return (NULL);
		}
		hostlen = len;
	}
	(void)strcpy(host, hp->h_name);

	/* Done if we aren't checking */
	if (!check)
		return (host);

#ifndef HAVE_GETHOSTBYNAME2
	if (af != AF_INET)
		return (NULL);
#endif

	/* Check PTR against the A record */
	if (tmo > 0)
		alarm(tmo);
	doingdns = 1;
	if (setjmp(alrmenv))
		return (NULL);
#ifdef HAVE_GETHOSTBYNAME2
	hp = gethostbyname2(host, af);
#else
	hp = gethostbyname(host);
#endif
	doingdns = 0;
	if (hp == NULL)
		return (NULL);
	if (af != hp->h_addrtype)
		return (NULL);

	/* Spin through ip addresses looking for a match */
	for (pp = hp->h_addr_list; *pp != NULL; ++pp)
		if (memcmp(ap, *pp, alen) == 0)
			return (host);

	return (NULL);
}

/* Convert address to hostname via the cache and/or dns */
char *
addr2host(register const char *ap, register int alen, register int af)
{
	register int state;
	register char *host;
	register struct htable *p;

	/* First look in hash table */
	p = lookupaddr(ap, alen, af);
	if (p != NULL)
		return (p->name);

	/* Lookup this host */
	host = a2h(ap, alen, af);
	state = STATE_RAW;
	if (host != NULL) {
		if (check)
			state = STATE_HAVEA;
		else
			state = STATE_HAVEPTR;
		massagename(host);
	}

	p = cacheaddr(ap, state, alen, af, host);
	if (p != NULL)
		return (p->name);

	return (host);
}

/* Look hash table entry for address */
struct htable *
lookupaddr(register const char *ap, register int alen, register int af)
{
	register struct htable *p;

	for (p = hash(ap, alen, af); p != NULL; p = p->next)
		if (p->af == af && memcmp(p->addr, ap, alen) == 0)
			return (p);
	return (NULL);
}

void
massagename(register char *name)
{
	register char *cp;

	if (shortdomain) {
		/* Throw away entire domain */
		cp = strchr(name, '.');
		if (cp)
			*cp = '\0';
	} else if (strip && *domain != '\0') {
		/* Strip the local domain */
		cp = name + strlen(name) - domainlen;
		if (cp > name && strcasecmp(cp, domain) == 0)
			*cp = '\0';
	}
	if (lcase)
		for (cp = name; *cp; ++cp)
			if (isupper((int)*cp))
				*cp = tolower(*cp);
}

struct htable *
cacheaddr(register const char *ap, register int state, register int alen,
    register int af, register const char *host)
{
	register struct htable *p, *p2;

	/* Don't cache zero */
	if (memcmp(ap, azero, alen) == 0)
		return (NULL);

	/* Look for existing slot in hash table */
	for (p = hash(ap, alen, af); p != NULL; p = p->next)
		if (p->state != STATE_FREE &&
		    p->af == af &&
		    memcmp(p->addr, ap, alen) == 0)
			break;

	/* Allocate a new slot */
	if (p == NULL) {
		p = hash(ap, alen, af);
		if (p->state != STATE_FREE) {
			/* Handle the collision */
			p2 = (struct htable *)malloc(sizeof(struct htable));
			/* Lose, lose */
			if (p2 == NULL)
				return (NULL);
			memset((char *)p2, 0, sizeof(struct htable));
			p2->next = p->next;
			p->next = p2;
			p = p2;
		}
	}

	/* Install new host */
	memmove(p->addr, ap, alen);
	p->alen = alen;
	p->af = af;
	if (host != NULL)
		p->name = strdup(host);
	if (state != 0)
		p->state = state;
	if (p->state == STATE_FREE)
		abort();

	/* Return answer entry */
	return (p);
}

#ifdef DEBUG
void
dump()
{
	register char *cp;
	register int i, j, n, d;
	register struct htable *p, *p2;
	char buf[132];

	d = n = 0;
	for (p = htable, i = 0; i < HSIZE; ++p, ++i)
		if (p->name) {
			++n;
			j = 0;
			for (p2 = p; p2; p2 = p2->next) {
				if ((cp = p2->name) == NULL)
					cp = "<nil>";
				else if (cp == (char *)1)
					cp = "<raw>";
				(void)fprintf(stderr, "%4d:%d ", i, j);
				if (inet_ntop(p2->af, p2->addr,
				    buf, sizeof(buf)) == NULL)
					(void)fprintf(stderr, "?");
				else
					(void)fprintf(stderr, "%s", buf);
				switch (p2->state) {

				case STATE_HAVEA:
					(void)fprintf(stderr, " HAVEA");
					break;

				case STATE_HAVEPTR:
					(void)fprintf(stderr, " HAVEPTR");
					break;

				case STATE_SENTPTR:
					(void)fprintf(stderr, " SENTPTR");
					break;

				case STATE_RAW:
					(void)fprintf(stderr, " RAW");
					break;

				default:
					(void)fprintf(stderr, " #%d",
					    p2->state);
					break;
				}
				(void)fprintf(stderr, " \"%s\"\n", cp);
				++d;
				++j;
			}
		}
	d -= n;
	(void)fprintf(stderr, "%d entries (%d dynamically linked)\n", n, d);
}
#endif

#ifdef HAVE_ASYNC_DNS
void
asyncreap(register int ateof)
{
	register char *host;
	register int n;
	register char **pp;
	register struct htable *p;
	register struct nb_dns_result *nr;
	register struct hostent *hp;
	fd_set fds;
	struct timeval to;
	char errstr[NB_DNS_ERRSIZE];
	struct nb_dns_result xxxnr;

	nr = &xxxnr;
	memset(nr, 0, sizeof(*nr));
	while (numasync > 0) {
		FD_ZERO(&fds);
		FD_SET(asyncfd, &fds);
		/* If we're not at EOF, just poll */
		if (!ateof) {
			to.tv_sec = 0;
			to.tv_usec = 0;
		} else {
			to.tv_sec = tmo;
			to.tv_usec = 0;
		}
		n = select(asyncfd + 1, &fds, NULL, NULL, &to);
		if (n < 0) {
			fprintf(stderr, "%s: select: %s\n",
			    prog, strerror(errno));
			exit(1);
		}

		/* Done if timed out */
		if (n == 0)
			break;

		n = nb_dns_activity(nd, nr, errstr);
		if (n < 0) {
			fprintf(stderr, "%s: nb_dns_activity: %s\n",
			    prog, errstr);
			exit(1);
		}

		/* Bail if reply doesn't match any current queries */
		if (n == 0)
			continue;

		/* Decrement outstanding request counter */
		--numasync;

		/* Bail if not a good answer */
		if (nr->host_errno != NETDB_SUCCESS)
			continue;

		/* Bail if no hostname (probably shouldn't happen) */
		hp = nr->hostent;
		host = hp->h_name;
		if (host == NULL)
			continue;

		/* Recover hash table pointer */
		p = (struct htable *)nr->cookie;

		switch (p->state) {

		case STATE_SENTPTR:
			/* Are we done? */
			if (!check) {
				p->state = STATE_HAVEPTR;
				break;
			}

			/* Now look up the A record */
			if (nb_dns_host_request2(nd, host, p->af,
			    (void *)p, errstr) < 0) {
				fprintf(stderr, "%s: nb_dns_host_request: %s\n",
				    prog, errstr);
				p->state = STATE_RAW;
				free(p->name);
				p->name = NULL;
				break;
			}

			/* Cache the fact that we're looking */
			++numasync;
			p->state = STATE_SENTA;
			break;

		case STATE_SENTA:
			/* Check A against our address */
			if (p->af != hp->h_addrtype) {
				p->state = STATE_RAW;
				free(p->name);
				p->name = NULL;
				break;
			}

			/* Spin through ip addresses looking for a match */
			for (pp = hp->h_addr_list; *pp != NULL; ++pp)
				if (memcmp(p->addr, *pp, p->alen) == 0)
					break;

			if (pp == NULL) {
				p->state = STATE_RAW;
				free(p->name);
				p->name = NULL;
				break;
			}
			p->state = STATE_HAVEA;
			break;

		default:
			abort();
		}
		massagename(host);
		if (p->name != NULL)
			abort();
		if (host != NULL)
			p->name = strdup(host);
	}
}
#endif

void
convert(register const char *str, register int isv6)
{
	register char *host;
	register int alen;
	register int af;
#ifdef HAVE_ASYNC_DNS
	register struct htable *p;
	char errstr[NB_DNS_ERRSIZE];
	static int num = 0;
#endif
	char addr[NS_IN6ADDRSZ];

	if (isv6) {
#ifdef AF_INET6
		af = AF_INET6;
		alen = NS_IN6ADDRSZ;
#else
#ifdef HAVE_ASYNC_DNS
		if (!asyncdns || !lookup_pass)
#endif
			fputs(str, stdout);
		return;
#endif
	} else {
		af = AF_INET;
		alen = NS_INADDRSZ;
	}

#ifdef HAVE_ASYNC_DNS
	if (asyncdns && lookup_pass) {
		if (inet_pton(af, str, addr) != 1)
			return;

		/* Done if already in hash table */
		if (lookupaddr(addr, alen, af) != NULL)
			return;

		p = cacheaddr(addr, STATE_SENTPTR, alen, af, NULL);
		if (p == NULL)
			return;

		if (nb_dns_addr_request2(nd, addr, af,
		    (void *)p, errstr) >= 0) {
			/* Cache the fact that we're looking */
			++numasync;
			++num;
		} else
			fprintf(stderr, "%s: nb_dns_host_request: %s\n",
			    prog, errstr);
		/* reap replies after we send a number of queries */
		if (num > 10) {
			asyncreap(0);
			num = 0;
		}
		return;
	}
#endif

	if (linemode && triedone) {
		fputs(str, stdout);
		return;
	}
	++triedone;

	if (inet_pton(af, str, addr) == 1) {
		host = addr2host(addr, alen, af);
		if (host != NULL) {
			fputs(host, stdout);
			if (printboth) {
				putchar('(');
				fputs(str, stdout);
				putchar(')');
			}
			return;
		}
	}
	fputs(str, stdout);
}

struct htable *
hash(register const char *ap, register int alen, register int af)
{
	u_int32_t h;

	switch (alen) {

	case NS_INADDRSZ:
		memmove(&h, ap, sizeof(h));
		break;

	case NS_IN6ADDRSZ:
		memmove(&h, ap + NS_IN6ADDRSZ - sizeof(h), sizeof(h));
		break;

	default:
		abort();
	}
	return (&htable[h & (HSIZE - 1)]);
}

#ifdef HAVE_ASYNC_DNS
int
ispipe(FILE *f)
{
	struct stat sbuf;

	if (fstat(fileno(f), &sbuf) < 0) {
		fprintf(stderr, "%s: fstat: %s\n", prog, strerror(errno));
		exit(1);
	}
	if ((sbuf.st_mode & S_IFMT) != S_IFREG)
		return (1);
	return (0);
}
#endif

void
usage()
{
	extern char version[];

	(void)fprintf(stderr, "Version %s\n", version);
	(void)fprintf(stderr, "usage: %s [-1abcdilN] [-t secs] [file ...]\n",
	    prog);
	exit(1);
}
