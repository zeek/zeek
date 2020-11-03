/*
 * See the file "COPYING" in the main distribution directory for copyright.
 */

#pragma once

#include <stdint.h>
#include <sys/socket.h>

/* Private data */
struct nb_dns_info;

/* Public data */
struct nb_dns_result {
	void *cookie;
	int host_errno;
	uint32_t ttl;
	struct hostent *hostent;
};

typedef unsigned int nb_uint32_t;

/* Public routines */
struct nb_dns_info *nb_dns_init(char *);
struct nb_dns_info *nb_dns_init2(char *, struct sockaddr*);
void nb_dns_finish(struct nb_dns_info *);

int nb_dns_fd(struct nb_dns_info *);

int nb_dns_host_request(struct nb_dns_info *, const char *, void *, char *);
int nb_dns_host_request2(struct nb_dns_info *, const char *, int, int,
				void *, char *);

int nb_dns_addr_request(struct nb_dns_info *, nb_uint32_t, void *, char *);
int nb_dns_addr_request2(struct nb_dns_info *, char *, int, void *, char *);

int nb_dns_abort_request(struct nb_dns_info *, void *);

int nb_dns_activity(struct nb_dns_info *, struct nb_dns_result *, char *);

#define NB_DNS_ERRSIZE 256
