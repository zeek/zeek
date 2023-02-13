/* Taken/adapted from FreeBSD 9.0.0 inet_ntop.c (CVS revision 1.3.16.1.2.1) */
/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "zeek_inet_ntop.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

/*%
 * WARNING: Don't even consider trying to compile this on a system where
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.
 */

static const char *zeek_inet_ntop4(const u_char *src, char *dst, socklen_t size);
static const char *zeek_inet_ntop6(const u_char *src, char *dst, socklen_t size);

/* char *
 * zeek_inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
const char *
zeek_inet_ntop(int af, const void * __restrict src, char * __restrict dst,
    socklen_t size)
{
	switch (af) {
	case AF_INET:
		return (zeek_inet_ntop4(src, dst, size));
	case AF_INET6:
		return (zeek_inet_ntop6(src, dst, size));
	default:
		errno = EAFNOSUPPORT;
		return (NULL);
	}
	/* NOTREACHED */
}

/* const char *
 * zeek_inet_ntop4(src, dst, size)
 *	format an IPv4 address
 * return:
 *	`dst' (as a const)
 * notes:
 *	(1) uses no statics
 *	(2) takes a u_char* not an in_addr as input
 * author:
 *	Paul Vixie, 1996.  Modified by Jon Siwek, 2012, to replace strlcpy
 */
static const char *
zeek_inet_ntop4(const u_char *src, char *dst, socklen_t size)
{
	static const char fmt[] = "%u.%u.%u.%u";
	char tmp[sizeof "255.255.255.255"];
	int l;

	l = snprintf(tmp, sizeof(tmp), fmt, src[0], src[1], src[2], src[3]);
	if (l <= 0 || (socklen_t) l >= size) {
		errno = ENOSPC;
		return (NULL);
	}
	strncpy(dst, tmp, size - 1);
	dst[size - 1] = 0;
	return (dst);
}

/* const char *
 * zeek_inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.  Modified by Jon Siwek, 2012, for IPv4-translated format
 */
static const char *
zeek_inet_ntop6(const u_char *src, char *dst, socklen_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	char tmp[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")], *tp;
	struct { int base, len; } best, cur;
	u_int words[NS_IN6ADDRSZ / NS_INT16SZ];
	int i;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(words, '\0', sizeof words);
	for (i = 0; i < NS_IN6ADDRSZ; i++)
		words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	best.len = 0;
	cur.base = -1;
	cur.len = 0;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		if (words[i] == 0) {
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else
				cur.len++;
		} else {
			if (cur.base != -1) {
				if (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1) {
		if (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	int remaining = sizeof(tmp);
	tp = tmp;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ) && remaining > 0; i++) {
		/* Are we inside the best run of 0x00's? */
		if (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			if (i == best.base)
				{
				*tp++ = ':';
				remaining--;
				}
			continue;
		}

		/* Are we following an initial run of 0x00s or any real hex? */
		if (i != 0)
			{
			*tp++ = ':';
			remaining--;
			}

		/* Is this address an encapsulated IPv4? */
		if (i == 6 && best.base == 0 && (best.len == 6 ||
		    (best.len == 7 && words[7] != 0x0001) ||
		    (best.len == 5 && words[5] == 0xffff) ||
		    (best.len == 4 && words[4] == 0xffff && words[5] == 0))) {
			if (!zeek_inet_ntop4(src+12, tp, sizeof tmp - (tp - tmp)))
				return (NULL);
			tp += strlen(tp);
			remaining -= strlen(tp);
			break;
		}

		// snprintf() returns the number of characters that were written not
		// including the null character. We can use that to increase the
		// pointer as we're moving forward. Unfortunately, snprintf() can also
		// return more than the value passed if it would have stepped off the
		// end.
		int ret = snprintf(tp, remaining, "%x" , words[i]);
		if ( ret < remaining )
			tp += ret;

		// Even if we returned too much data, subtract from remaining so that
		// the failure cases below get triggered.
		remaining -= ret;
	}

	/* Was it a trailing run of 0x00's? */
	if (remaining >= 2 &&
	    best.base != -1 &&
	    (best.base + best.len) == (NS_IN6ADDRSZ / NS_INT16SZ)) {
		*tp++ = ':';
		remaining--;
	}

	if ( remaining >= 1 ) {
		*tp++ = '\0';
		remaining--;
	}

	else if ( remaining <= 0 ) {
		errno = ENOSPC;
		return (NULL);
	}

	strcpy(dst, tmp);
	return (dst);
}
