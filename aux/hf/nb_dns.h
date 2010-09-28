/* @(#) $Id: nb_dns.h 909 2004-12-09 04:27:10Z jason $ (LBL)
 *
 * Copyright (c) 2000, 2002
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

/* Private data */
struct nb_dns_info;

/* Public data */
struct nb_dns_result {
	void *cookie;
	int host_errno;
	struct hostent *hostent;
};

typedef unsigned int nb_uint32_t;

/* Public routines */
struct nb_dns_info *nb_dns_init(char *);
void nb_dns_finish(struct nb_dns_info *);

int nb_dns_fd(struct nb_dns_info *);

int nb_dns_host_request(struct nb_dns_info *, const char *, void *, char *);
int nb_dns_host_request2(struct nb_dns_info *, const char *, int,
    void *, char *);

int nb_dns_addr_request(struct nb_dns_info *, nb_uint32_t, void *, char *);
int nb_dns_addr_request2(struct nb_dns_info *, char *, int, void *, char *);

int nb_dns_abort_request(struct nb_dns_info *, void *);

int nb_dns_activity(struct nb_dns_info *, struct nb_dns_result *, char *);

#define NB_DNS_ERRSIZE 256
