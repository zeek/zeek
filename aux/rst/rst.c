/* $Id: rst.c 7073 2010-09-13 00:45:02Z vern $ */

/* Derived from traceroute, which has the following copyright:
 *
 * Copyright (c) 1999, 2002
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
    "@(#) Copyright (c) 1999, 2002\nThe Regents of the University of California.  All rights reserved.\n";
static const char rcsid[] =
    "@(#) $Id: rst.c 7073 2010-09-13 00:45:02Z vern $ (LBL)";
#endif

/* need this due to linux's funny idea of a tcphdr */
#if defined(__linux__)
#define _BSD_SOURCE
#endif

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../config.h"

/* Forwards */
void gripe(const char *, const char *);
void pgripe(const char *);
u_short in_cksum(register u_short *, register int);
int ones_complement_checksum(const void *, int, u_int32_t);
int tcp_checksum(const struct ip *, const struct tcphdr *, int);
void send_pkt(int, struct in_addr, int, u_int32_t, struct in_addr,
    int, u_int32_t, int, int, int, int, const char *);
void terminate(int, const char *, int, u_int32_t, const char *,
    int, u_int32_t, int, int, int, int, const char *);
void usage(void);
int main(int, char **);

const char *prog_name;

void gripe(const char *fmt, const char *arg)
{
	fprintf(stderr, "%s: ", prog_name);
	fprintf(stderr, fmt, arg);
	fprintf(stderr, "\n");
}

void pgripe(const char *msg)
{
	fprintf(stderr, "%s: %s (%s)\n", prog_name, msg, strerror(errno));
	exit(1);
}

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 */
u_short
in_cksum(register u_short *addr, register int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register u_short answer;
	register int sum = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += *(u_char *)w;

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

// - adapted from tcpdump
// Returns the ones-complement checksum of a chunk of b short-aligned bytes.
int ones_complement_checksum(const void *p, int b, u_int32_t sum)
{
	const u_short *sp = (u_short *) p;	// better be aligned!

	b /= 2;	// convert to count of short's

	/* No need for endian conversions. */
	while ( --b >= 0 )
		sum += *sp++;

	while ( sum > 0xffff )
		sum = (sum & 0xffff) + (sum >> 16);

	return sum;
}

int tcp_checksum(const struct ip *ip, const struct tcphdr *tp, int len)
{
	int tcp_len = tp->th_off * 4 + len;
	u_int32_t sum, addl_pseudo;

	if ( len % 2 == 1 )
		// Add in pad byte.
		sum = htons(((const u_char*) tp)[tcp_len - 1] << 8);
	else
		sum = 0;

	sum = ones_complement_checksum((void*) &ip->ip_src.s_addr, 4, sum);
	sum = ones_complement_checksum((void*) &ip->ip_dst.s_addr, 4, sum);

	addl_pseudo = (htons(IPPROTO_TCP) << 16) | htons((unsigned short) tcp_len);

	sum = ones_complement_checksum((void*) &addl_pseudo, 4, sum);
	sum = ones_complement_checksum((void*) tp, tcp_len, sum);

	return sum;
}

void send_pkt(int s, struct in_addr from, int from_port, u_int32_t from_seq,
		struct in_addr to, int to_port, u_int32_t to_seq,
		int size, int redundancy, int delay, int flags,
		const char *inject)
{
	int cc;
	int pktlen = 40 + size;
	const int max_injection_size = 4096;
	char *pkt = malloc(pktlen + max_injection_size + 1024 /* slop */);
	struct ip *ip = (struct ip *) pkt;
	struct tcphdr *tcp = (struct tcphdr *) &pkt[20];

	if ( ! pkt )
		pgripe("couldn't malloc memory");

	if ( inject && *inject ) {
		size = strlen(inject);

		if ( size > max_injection_size )
			gripe("injection text too large%s", "");

		pktlen = 40 + size;
	}

	memset(pkt, 0, pktlen);

	ip->ip_v = IPVERSION;
	ip->ip_len = pktlen;	/* on FreeBSD, don't use htons(); YMMV */
	ip->ip_off = 0;
	ip->ip_src = from;
	ip->ip_dst = to;
	ip->ip_hl = 5;
	ip->ip_p = IPPROTO_TCP;
	ip->ip_ttl = 255;
	ip->ip_id = 0;

	ip->ip_sum = in_cksum((u_short *) ip, sizeof(*ip));

	if (ip->ip_sum == 0)
		ip->ip_sum = 0xffff;

	tcp->th_sport = htons(from_port);
	tcp->th_dport = htons(to_port);
	tcp->th_seq = htonl(from_seq);
	tcp->th_ack = htonl(to_seq);
	tcp->th_off = 5;
	tcp->th_flags = flags;
	tcp->th_win = 0;
	tcp->th_urp = 0;
	tcp->th_sum = 0;

	if ( inject && *inject ) {
		char *payload = &pkt[40];
		strcpy(payload, inject);

	} else if ( size > 0 )
		{
		const char *fill_string =
			(inject && *inject) ? inject : "BRO-RST\n";
		char *payload = &pkt[40];
		int n = strlen(fill_string);
		int i;
		for ( i = size; i > n + 1; i -= n )
			{
			strcpy(payload, fill_string);
			payload += n;
			}

		for ( ; i > 0; --i )
			*(payload++) = '\n';
		}

	tcp->th_sum = ~tcp_checksum(ip, tcp, size);

	while ( redundancy-- > 0 )
		{
		cc = send(s, (char *) ip, pktlen, 0);
		if (cc < 0 || cc != pktlen)
			pgripe("problem in sendto()");
		usleep(delay * 1000);
		}

	free(pkt);
}

void terminate(int s, const char *from_addr, int from_port, u_int32_t from_seq,
		const char *to_addr, int to_port, u_int32_t to_seq,
		int num, int redundancy, int stride, int delay,
		const char *inject)
{
	struct sockaddr where_from, where_to;
	struct sockaddr_in *from = (struct sockaddr_in *) &where_from;
	struct sockaddr_in *to = (struct sockaddr_in *) &where_to;

	memset(from, 0, sizeof(*from));
	memset(to, 0, sizeof(*to));
#ifdef SIN_LEN
	from->sin_len = to->sin_len = sizeof(*to);
#endif /* SIN_LEN */
	from->sin_family = to->sin_family = AF_INET;

	if ( inet_aton(from_addr, (struct in_addr *) &from->sin_addr) == 0 )
		gripe("bad from address %s", from_addr);
	if ( inet_aton(to_addr, (struct in_addr *) &to->sin_addr) == 0 )
		gripe("bad to address %s", to_addr);

	if ( connect(s, &where_to, sizeof(where_to)) < 0 )
		pgripe("can't connect");

	while ( num-- > 0 )
		{
		send_pkt(s, from->sin_addr, from_port, from_seq,
			to->sin_addr, to_port, to_seq, 0, redundancy, delay,
			(*inject ? 0 : TH_RST) | TH_ACK, inject);

		if ( num > 0 && stride > 1 )
			send_pkt(s, from->sin_addr, from_port, from_seq,
				to->sin_addr, to_port, to_seq, stride,
				redundancy, delay, TH_ACK, inject);

		from_seq += stride;
		}
}

void usage()
{
	fprintf(stderr, "%s [-R] [-I text-to-inject] [-d delay-msec] [-n num] [-r redundancy] [-s stride] from_addr from_port from_seq to_addr to_port to_seq\n", prog_name);
	exit(0);
}

int main(int argc, char **argv)
{
	extern char* optarg;
	extern int optind, opterr;
	const char *from_addr, *to_addr;
	char inject[8192];
	int from_port, to_port;
	u_int32_t from_seq, to_seq;
	int delay = 0.0;
	int redundancy = 1;
	int num = 1;
	int stride = 1;
	int reverse = 0;
	int s;
	int on = 1;
	int op;

	prog_name = argv[0];

	opterr = 0;

	inject[0] = 0;

	while ( (op = getopt(argc, argv, "RI:d:n:r:s:")) != EOF )
		switch ( op ) {
		case 'R':
			reverse = 1;
			break;

		case 'I':
			{
			char *ap = optarg;
			char *ip;
			for ( ip = inject; *ap; ++ip, ++ap ) {
				if ( ap[0] == '\\' && ap[1] == 'n' )
					*ip = '\n', ++ap;
				else
					*ip = *ap;
			}
			}
			break;

		case 'd':
			delay = atoi(optarg);
			break;

		case 'n':
			num = atoi(optarg);
			break;

		case 'r':
			redundancy = atoi(optarg);
			break;

		case 's':
			stride = atoi(optarg);
			break;

		default:
			usage();
			break;
		}

	if ( argc - optind != 6 )
		usage();

	s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if ( s < 0 )
		pgripe("couldn't create raw socket");

	setuid(getuid());

	if (setsockopt(s, 0, IP_HDRINCL, (char *) &on, sizeof(on)) < 0)
		pgripe("can't turn on IP_HDRINCL");

	from_addr = argv[optind++];
	from_port = atoi(argv[optind++]);
	from_seq = strtoul(argv[optind++], 0, 10);

	to_addr = argv[optind++];
	to_port = atoi(argv[optind++]);
	to_seq = strtoul(argv[optind++], 0, 10);

	if ( reverse )
		terminate(s, to_addr, to_port, to_seq,
			from_addr, from_port, from_seq,
			num, redundancy, stride, delay, inject);
	else
		terminate(s, from_addr, from_port, from_seq,
			to_addr, to_port, to_seq,
			num, redundancy, stride, delay, inject);

	return 0;
}
