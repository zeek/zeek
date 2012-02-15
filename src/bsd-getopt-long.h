/*    $OpenBSD: getopt_long.c,v 1.13 2003/06/03 01:52:40 millert Exp $    */
/*    $NetBSD: getopt_long.c,v 1.15 2002/01/31 22:43:40 tv Exp $    */

/*
 * Copyright (c) 2002 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND TODD C. MILLER DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL TODD C. MILLER BE LIABLE
 * FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/*-
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Dieter Baron and Thomas Klausner.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __BSD_GETOPT_LONG_H__
#define __BSD_GETOPT_LONG_H__

#ifndef HAVE_GETOPT_LONG

/*
 * GNU-like getopt_long() and 4.4BSD getsubopt()/optreset extensions
 */
# ifndef no_argument
#  define no_argument        0
# endif
# ifndef required_argument
#  define required_argument  1
# endif
# ifndef optional_argument
#  define optional_argument  2
# endif

struct pure_option {
    /* name of long option */
    const char *name;
    /*
     * one of no_argument, required_argument, and optional_argument:
     * whether option takes an argument
     */
    int has_arg;
    /* if not NULL, set *flag to val when option found */
    int *flag;
    /* if flag not NULL, value to set *flag to; else return value */
    int val;
};

#ifdef __cplusplus
extern "C" {
#endif

int pure_getopt_long(int nargc, char * const *nargv, const char *options,
                     const struct pure_option *long_options, int *idx);

int pure_getopt_long_only(int nargc, char * const *nargv,
                          const char *options,
                          const struct pure_option *long_options,
                          int *idx);

int pure_getopt(int nargc, char * const *nargv, const char *options);

#ifdef __cplusplus
}
#endif

/* prefix+macros just to avoid clashes with existing getopt() implementations */

# ifndef IN_GETOPT_LONG_C
#  undef option
#  define option pure_option
#  undef getopt_long
#  define getopt_long(A, B, C, D, E) pure_getopt_long(A, B, C, D, E)
#  undef getopt_long_only
#  define getopt_long_only(A, B, C, D, E) pure_getopt_long_only(A, B, C, D, E)
#  undef getopt
#  define getopt(A, B, C) pure_getopt(A, B, C)
#  undef optarg
#  define optarg pure_optarg
#  undef opterr
#  define opterr pure_opterr
#  undef optind
#  define optind pure_optind
#  undef optopt
#  define optopt pure_optopt
#  undef optreset
#  define optreset pure_optreset
# endif

#endif

#endif
