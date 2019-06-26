/*
 * See the file "COPYING" in the main distribution directory for copyright.
 */
/*
 * nb_dns - non-blocking dns routines
 *
 * This version works with BIND 9
 *
 * Note: The code here is way more complicated than it should be but
 * although the interface to send requests is public, the routine to
 * crack reply buffers is private.
 */

#include "zeek-config.h"			/* must appear before first ifdef */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#ifdef NEED_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif

#include <errno.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef notdef
#include "gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif
#endif

#include "nb_dns.h"

#if PACKETSZ > 1024
#define MAXPACKET	PACKETSZ
#else
#define MAXPACKET	1024
#endif

#ifdef DO_SOCK_DECL
extern int socket(int, int, int);
extern int connect(int, const struct sockaddr *, int);
extern int send(int, const void *, int, int);
extern int recvfrom(int, void *, int, int, struct sockaddr *, int *);
#endif

/* Private data */
struct nb_dns_entry {
	struct nb_dns_entry *next;
	char name[NS_MAXDNAME + 1];
	int qtype;			/* query type */
	int atype;			/* address family */
	int asize;			/* address size */
	u_short id;
	void *cookie;
};

#ifndef MAXALIASES
#define MAXALIASES	35
#endif
#ifndef MAXADDRS
#define MAXADDRS	35
#endif

struct nb_dns_hostent {
	struct hostent hostent;
	int numaliases;
	int numaddrs;
	char *host_aliases[MAXALIASES + 1];
	char *h_addr_ptrs[MAXADDRS + 1];
	char hostbuf[8 * 1024];
};

struct nb_dns_info {
	int s;				/* Resolver file descriptor */
	struct sockaddr_storage server;	/* server address to bind to */
	struct nb_dns_entry *list;	/* outstanding requests */
	struct nb_dns_hostent dns_hostent;
};

/* Forwards */
static int _nb_dns_mkquery(struct nb_dns_info *, const char *, int, int,
    void *, char *);
static int _nb_dns_cmpsockaddr(struct sockaddr *, struct sockaddr *, char *);

static char *
my_strerror(int errnum)
{
#ifdef HAVE_STRERROR
	extern char *strerror(int);
	return strerror(errnum);
#else
	static char errnum_buf[32];
	snprintf(errnum_buf, sizeof(errnum_buf), "errno %d", errnum);
	return errnum_buf;
#endif
}

static const char* sa_ntop(struct sockaddr* sa, char* buf, int len)
	{
	if ( sa->sa_family == AF_INET )
		return inet_ntop(sa->sa_family,
		                 &(((struct sockaddr_in*)sa)->sin_addr),
		                 buf, len);
	else
		return inet_ntop(sa->sa_family,
		                 &(((struct sockaddr_in6*)sa)->sin6_addr),
		                 buf, len);
	}

struct nb_dns_info *
nb_dns_init(char *errstr)
{
	register struct nb_dns_info *nd;

	nd = (struct nb_dns_info *)malloc(sizeof(*nd));
	if (nd == NULL) {
		snprintf(errstr, NB_DNS_ERRSIZE, "nb_dns_init: malloc(): %s",
		    my_strerror(errno));
		return (NULL);
	}
	memset(nd, 0, sizeof(*nd));
	nd->s = -1;

	/* XXX should be able to init static hostent struct some other way */
	(void)gethostbyname("localhost");

	if ((_res.options & RES_INIT) == 0 && res_init() == -1) {
		snprintf(errstr, NB_DNS_ERRSIZE, "res_init() failed");
		free(nd);
		return (NULL);
	}

	if ( _res.nscount == 0 )
		{
		// Really?  Let's try parsing resolv.conf ourselves to see what's
		// there.  (e.g. musl libc has res_init() that doesn't actually
		// parse the config file).
		const char* config_file_path = "/etc/resolv.conf";

#ifdef _PATH_RESCONF
		config_file_path = _PATH_RESCONF;
#endif

		FILE* config_file = fopen(config_file_path, "r");

		if ( config_file )
			{
			char line[128];
			char* ns;

			while ( fgets(line, sizeof(line), config_file) )
				{
				ns = strtok(line, " \t\n");

				if ( ! ns || strcmp(ns, "nameserver") )
					continue;

				ns = strtok(0, " \t\n");

				if ( ! ns )
					continue;

				/* XXX support IPv6 */
				struct sockaddr_in a;
				memset(&a, 0, sizeof(a));
				a.sin_family = AF_INET;
				a.sin_port = htons(53);

				if ( inet_pton(AF_INET, ns, &a.sin_addr) == 1 )
					{
					memcpy(&nd->server, &a, sizeof(a));
					nd->s = socket(nd->server.ss_family, SOCK_DGRAM, 0);

					if ( nd->s < 0 )
						{
						snprintf(errstr, NB_DNS_ERRSIZE, "socket(): %s",
						         my_strerror(errno));
						fclose(config_file);
						free(nd);
						return (NULL);
						}

					if ( connect(nd->s, (struct sockaddr *)&nd->server,
					             nd->server.ss_family == AF_INET ?
					             sizeof(struct sockaddr_in) :
					             sizeof(struct sockaddr_in6)) < 0 )
						{
						char s[INET6_ADDRSTRLEN];
						sa_ntop((struct sockaddr*)&nd->server, s, INET6_ADDRSTRLEN);
						snprintf(errstr, NB_DNS_ERRSIZE, "connect(%s): %s", s,
						         my_strerror(errno));
						fclose(config_file);
						close(nd->s);
						free(nd);
						return (NULL);
						}

					fclose(config_file);
					return (nd);
					}
				}

			fclose(config_file);
			snprintf(errstr, NB_DNS_ERRSIZE, "no valid nameserver found in %s",
			         config_file_path);
			free(nd);
			return (NULL);
			}

		snprintf(errstr, NB_DNS_ERRSIZE, "resolver config file not located");
		free(nd);
		return (NULL);
		}

	int i;

	for ( i = 0; i < _res.nscount; ++i )
		{
		memcpy(&nd->server, &_res.nsaddr_list[i], sizeof(struct sockaddr_in));
		/* XXX support IPv6 */
		if ( nd->server.ss_family != AF_INET )
			continue;

		nd->s = socket(nd->server.ss_family, SOCK_DGRAM, 0);

		if ( nd->s < 0 )
			{
			snprintf(errstr, NB_DNS_ERRSIZE, "socket(): %s",
			         my_strerror(errno));
			free(nd);
			return (NULL);
			}

		if ( connect(nd->s, (struct sockaddr *)&nd->server,
	                 nd->server.ss_family == AF_INET ?
	                           sizeof(struct sockaddr_in) :
	                           sizeof(struct sockaddr_in6)) < 0 )
			{
			char s[INET6_ADDRSTRLEN];
			sa_ntop((struct sockaddr*)&nd->server, s, INET6_ADDRSTRLEN);
			snprintf(errstr, NB_DNS_ERRSIZE, "connect(%s): %s", s,
			         my_strerror(errno));
			close(nd->s);
			free(nd);
			return (NULL);
			}

		return (nd);
		}

	snprintf(errstr, NB_DNS_ERRSIZE, "no valid nameservers in resolver config");
	free(nd);
	return (NULL);
}

struct nb_dns_info *
nb_dns_init2(char *errstr, struct sockaddr* sa)
{
	register struct nb_dns_info *nd;

	nd = (struct nb_dns_info *)malloc(sizeof(*nd));
	if (nd == NULL) {
		snprintf(errstr, NB_DNS_ERRSIZE, "nb_dns_init: malloc(): %s",
		    my_strerror(errno));
		return (NULL);
	}
	memset(nd, 0, sizeof(*nd));
	nd->s = -1;

	if ( sa->sa_family == AF_INET )
		{
		memcpy(&nd->server, sa, sizeof(struct sockaddr_in));
		((struct sockaddr_in*)&nd->server)->sin_port = htons(53);
		}
	else
		{
		memcpy(&nd->server, sa, sizeof(struct sockaddr_in6));
		((struct sockaddr_in6*)&nd->server)->sin6_port = htons(53);
		}

	nd->s = socket(nd->server.ss_family, SOCK_DGRAM, 0);

	if ( nd->s < 0 )
		{
		snprintf(errstr, NB_DNS_ERRSIZE, "socket(): %s",
		         my_strerror(errno));
		free(nd);
		return (NULL);
		}

	if ( connect(nd->s, (struct sockaddr *)&nd->server,
	             nd->server.ss_family == AF_INET ?
	                       sizeof(struct sockaddr_in) :
	                       sizeof(struct sockaddr_in6)) < 0 )
		{
		char s[INET6_ADDRSTRLEN];
		sa_ntop((struct sockaddr*)&nd->server, s, INET6_ADDRSTRLEN);
		snprintf(errstr, NB_DNS_ERRSIZE, "connect(%s): %s", s,
		         my_strerror(errno));
		close(nd->s);
		free(nd);
		return (NULL);
		}

	return (nd);
}

void
nb_dns_finish(struct nb_dns_info *nd)
{
	register struct nb_dns_entry *ne, *ne2;

	ne = nd->list;
	while (ne != NULL) {
		ne2 = ne;
		ne = ne->next;
		free(ne2);
	}
	close(nd->s);
	free(nd);
}

int
nb_dns_fd(struct nb_dns_info *nd)
{

	return (nd->s);
}

static int
_nb_dns_cmpsockaddr(register struct sockaddr *sa1,
    register struct sockaddr *sa2, register char *errstr)
{
	register struct sockaddr_in *sin1, *sin2;
#ifdef AF_INET6
	register struct sockaddr_in6 *sin6a, *sin6b;
#endif
	static const char serr[] = "answer from wrong nameserver (%d)";

	if (sa1->sa_family != sa2->sa_family) {
		snprintf(errstr, NB_DNS_ERRSIZE, serr, 1);
		return (-1);
	}
	switch (sa1->sa_family) {

	case AF_INET:
		sin1 = (struct sockaddr_in *)sa1;
		sin2 = (struct sockaddr_in *)sa2;
		if (sin1->sin_port != sin2->sin_port) {
			snprintf(errstr, NB_DNS_ERRSIZE, serr, 2);
			return (-1);
		}
		if (sin1->sin_addr.s_addr != sin2->sin_addr.s_addr) {
			snprintf(errstr, NB_DNS_ERRSIZE, serr, 3);
			return (-1);
		}
		break;

#ifdef AF_INET6
	case AF_INET6:
		sin6a = (struct sockaddr_in6 *)sa1;
		sin6b = (struct sockaddr_in6 *)sa2;
		if (sin6a->sin6_port != sin6b->sin6_port) {
			snprintf(errstr, NB_DNS_ERRSIZE, serr, 62);
			return (-1);
		}
		if (memcmp(&sin6a->sin6_addr, &sin6b->sin6_addr,
		    sizeof(sin6a->sin6_addr)) != 0) {
			snprintf(errstr, NB_DNS_ERRSIZE, serr, 63);
			return (-1);
		}
		break;
#endif

	default:
		snprintf(errstr, NB_DNS_ERRSIZE, serr, 4);
		return (-1);
	}
	return (0);
}

static int
_nb_dns_mkquery(register struct nb_dns_info *nd, register const char *name,
    register int atype, register int qtype, register void * cookie,
    register char *errstr)
{
	register struct nb_dns_entry *ne;
	register HEADER *hp;
	register int n;
	u_long msg[MAXPACKET / sizeof(u_long)];

	/* Allocate an entry */
	ne = (struct nb_dns_entry *)malloc(sizeof(*ne));
	if (ne == NULL) {
		snprintf(errstr, NB_DNS_ERRSIZE, "malloc(): %s",
		    my_strerror(errno));
		return (-1);
	}
	memset(ne, 0, sizeof(*ne));
	strncpy(ne->name, name, sizeof(ne->name));
	ne->name[sizeof(ne->name) - 1] = '\0';
	ne->qtype = qtype;
	ne->atype = atype;
	switch (atype) {

	case AF_INET:
		ne->asize = NS_INADDRSZ;
		break;

#ifdef AF_INET6
	case AF_INET6:
		ne->asize = NS_IN6ADDRSZ;
		break;
#endif

	default:
		snprintf(errstr, NB_DNS_ERRSIZE,
		    "_nb_dns_mkquery: bad family %d", atype);
		free(ne);
		return (-1);
	}

	/* Build the request */
	n = res_mkquery(
	    ns_o_query,			/* op code (query) */
	    name,			/* domain name */
	    ns_c_in,			/* query class (internet) */
	    qtype,			/* query type */
	    NULL,			/* data */
	    0,				/* length of data */
	    NULL,			/* new rr */
	    (u_char *)msg,		/* buffer */
	    sizeof(msg));		/* size of buffer */
	if (n < 0) {
		snprintf(errstr, NB_DNS_ERRSIZE, "res_mkquery() failed");
		free(ne);
		return (-1);
	}

	hp = (HEADER *)msg;
	ne->id = htons(hp->id);

	if (send(nd->s, (char *)msg, n, 0) != n) {
		snprintf(errstr, NB_DNS_ERRSIZE, "send(): %s",
		    my_strerror(errno));
		free(ne);
		return (-1);
	}

	ne->next = nd->list;
	ne->cookie = cookie;
	nd->list = ne;

	return(0);
}

int
nb_dns_host_request(register struct nb_dns_info *nd, register const char *name,
    register void *cookie, register char *errstr)
{

	return (nb_dns_host_request2(nd, name, AF_INET, 0, cookie, errstr));
}

int
nb_dns_host_request2(register struct nb_dns_info *nd, register const char *name,
    register int af, register int qtype, register void *cookie, register char *errstr)
{
	if (qtype != 16) {

		switch (af) {

		case AF_INET:
			qtype = T_A;
			break;

#ifdef AF_INET6
		case AF_INET6:
			qtype = T_AAAA;
			break;
#endif

		default:
			snprintf(errstr, NB_DNS_ERRSIZE,
			    "nb_dns_host_request2(): unknown address family %d", af);
			return (-1);
		}
	}
	return (_nb_dns_mkquery(nd, name, af, qtype, cookie, errstr));
}

int
nb_dns_addr_request(register struct nb_dns_info *nd, nb_uint32_t addr,
    register void *cookie, register char *errstr)
{

	return (nb_dns_addr_request2(nd, (char *)&addr, AF_INET,
	    cookie, errstr));
}

int
nb_dns_addr_request2(register struct nb_dns_info *nd, char *addrp,
    register int af, register void *cookie, register char *errstr)
{
#ifdef AF_INET6
	register char *cp;
	register int n, i;
	register size_t size;
#endif
	register u_char *uaddr;
	char name[NS_MAXDNAME + 1];

	switch (af) {

	case AF_INET:
		uaddr = (u_char *)addrp;
		snprintf(name, sizeof(name), "%u.%u.%u.%u.in-addr.arpa",
		    (uaddr[3] & 0xff),
		    (uaddr[2] & 0xff),
		    (uaddr[1] & 0xff),
		    (uaddr[0] & 0xff));
		break;

#ifdef AF_INET6
	case AF_INET6:
		uaddr = (u_char *)addrp;
		cp = name;
		size = sizeof(name);
		for (n = NS_IN6ADDRSZ - 1; n >= 0; --n) {
			snprintf(cp, size, "%x.%x.",
			    (uaddr[n] & 0xf),
			    (uaddr[n] >> 4) & 0xf);
			i = strlen(cp);
			size -= i;
			cp += i;
		}
		snprintf(cp, size, "ip6.arpa");
		break;
#endif

	default:
		snprintf(errstr, NB_DNS_ERRSIZE,
		    "nb_dns_addr_request2(): unknown address family %d", af);
		return (-1);
	}

	return (_nb_dns_mkquery(nd, name, af, T_PTR, cookie, errstr));
}

int
nb_dns_abort_request(struct nb_dns_info *nd, void *cookie)
{
	register struct nb_dns_entry *ne, *lastne;

	/* Try to find this request on the outstanding request list */
	lastne = NULL;
	for (ne = nd->list; ne != NULL; ne = ne->next) {
		if (ne->cookie == cookie)
			break;
		lastne = ne;
	}

	/* Not a currently pending request */
	if (ne == NULL)
		return (-1);

	/* Unlink this entry */
	if (lastne == NULL)
		nd->list = ne->next;
	else
		lastne->next = ne->next;
	ne->next = NULL;

	return (0);
}

/* Returns 1 with an answer, 0 when reply was old, -1 on fatal errors */
int
nb_dns_activity(struct nb_dns_info *nd, struct nb_dns_result *nr, char *errstr)
{
	register int msglen, qtype, atype, n, i;
	register struct nb_dns_entry *ne, *lastne;
	socklen_t fromlen;
	struct sockaddr_storage from;
	u_long msg[MAXPACKET / sizeof(u_long)];
	register char *bp, *ep;
	register char **ap, **hap;
	register u_int16_t id;
	register const u_char *rdata;
	register u_int32_t rttl = 0;	// make compiler happy.
	register struct hostent *he;
	register size_t rdlen;
	ns_msg handle;
	ns_rr rr;

	/* This comes from the second half of do_query() */
	fromlen = sizeof(from);
	msglen = recvfrom(nd->s, (char *)msg, sizeof(msg), 0,
	                  (struct sockaddr*)&from, &fromlen);
	if (msglen <= 0) {
		snprintf(errstr, NB_DNS_ERRSIZE, "recvfrom(): %s",
		    my_strerror(errno));
		return (-1);
	}
	if (msglen < HFIXEDSZ) {
		snprintf(errstr, NB_DNS_ERRSIZE, "recvfrom(): undersized: %d",
		    msglen);
		return (-1);
	}
	if (ns_initparse((u_char *)msg, msglen, &handle) < 0) {
		snprintf(errstr, NB_DNS_ERRSIZE, "ns_initparse(): %s",
		    my_strerror(errno));
		nr->host_errno = NO_RECOVERY;
		return (-1);
	}

	/* RES_INSECURE1 style check */
	if (_nb_dns_cmpsockaddr((struct sockaddr*)&nd->server,
	                        (struct sockaddr*)&from, errstr) < 0) {
		nr->host_errno = NO_RECOVERY;
		return (-1);
	}

	/* Search for this request */
	lastne = NULL;
	id = ns_msg_id(handle);
	for (ne = nd->list; ne != NULL; ne = ne->next) {
		if (ne->id == id)
			break;
		lastne = ne;
	}

	/* Not an answer to a question we care about anymore */
	if (ne == NULL)
		return (0);

	/* Unlink this entry */
	if (lastne == NULL)
		nd->list = ne->next;
	else
		lastne->next = ne->next;
	ne->next = NULL;

	/* RES_INSECURE2 style check */
	/* XXX not implemented */

	/* Initialize result struct */
	memset(nr, 0, sizeof(*nr));
	nr->cookie = ne->cookie;
	qtype = ne->qtype;

	/* Deal with various errors */
	switch (ns_msg_getflag(handle, ns_f_rcode)) {

	case ns_r_nxdomain:
		nr->host_errno = HOST_NOT_FOUND;
		free(ne);
		return (1);

	case ns_r_servfail:
		nr->host_errno = TRY_AGAIN;
		free(ne);
		return (1);

	case ns_r_noerror:
		break;

	case ns_r_formerr:
	case ns_r_notimpl:
	case ns_r_refused:
	default:
		nr->host_errno = NO_RECOVERY;
		free(ne);
		return (1);
	}

	/* Loop through records in packet */
	memset(&rr, 0, sizeof(rr));
	memset(&nd->dns_hostent, 0, sizeof(nd->dns_hostent));
	he = &nd->dns_hostent.hostent;
	/* XXX no support for aliases */
	he->h_aliases = nd->dns_hostent.host_aliases;
	he->h_addr_list = nd->dns_hostent.h_addr_ptrs;
	he->h_addrtype = ne->atype;
	he->h_length = ne->asize;
	free(ne);

	bp = nd->dns_hostent.hostbuf;
	ep = bp + sizeof(nd->dns_hostent.hostbuf);
	hap = he->h_addr_list;
	ap = he->h_aliases;

	for (i = 0; i < ns_msg_count(handle, ns_s_an); i++) {
		/* Parse next record */
		if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) {
			if (errno != ENODEV) {
				nr->host_errno = NO_RECOVERY;
				return (1);
			}
			/* All done */
			break;
		}

		/* Ignore records that don't answer our query (e.g. CNAMEs) */
		atype = ns_rr_type(rr);
		if (atype != qtype)
			continue;

		rdata = ns_rr_rdata(rr);
		rdlen = ns_rr_rdlen(rr);
		rttl = ns_rr_ttl(rr);
		switch (atype) {

		case T_A:
		case T_AAAA:
			if (rdlen != (unsigned int) he->h_length) {
				snprintf(errstr, NB_DNS_ERRSIZE,
				    "nb_dns_activity(): bad rdlen %d",
				    (int) rdlen);
				nr->host_errno = NO_RECOVERY;
				return (-1);
			}

			if (bp + rdlen >= ep) {
				snprintf(errstr, NB_DNS_ERRSIZE,
				    "nb_dns_activity(): overflow 1");
				nr->host_errno = NO_RECOVERY;
				return (-1);
			}
			if (nd->dns_hostent.numaddrs + 1 >= MAXADDRS) {
				snprintf(errstr, NB_DNS_ERRSIZE,
				    "nb_dns_activity(): overflow 2");
				nr->host_errno = NO_RECOVERY;
				return (-1);
			}

			memcpy(bp, rdata, rdlen);
			*hap++ = bp;
			bp += rdlen;
			++nd->dns_hostent.numaddrs;

			/* Keep looking for more A records */
			break;

		case T_TXT:
			if (bp + rdlen >= ep) {
				snprintf(errstr, NB_DNS_ERRSIZE,
				    "nb_dns_activity(): overflow 1 for txt");
				nr->host_errno = NO_RECOVERY;
				return (-1);
			}

			memcpy(bp, rdata, rdlen);
			he->h_name = bp+1; /* First char is a control character. */
			nr->hostent = he;
			nr->ttl = rttl;
			return (1);

		case T_PTR:
			n = dn_expand((const u_char *)msg,
			    (const u_char *)msg + msglen, rdata, bp, ep - bp);
			if (n < 0) {
				/* XXX return -1 here ??? */
				nr->host_errno = NO_RECOVERY;
				return (1);
			}
			he->h_name = bp;
			/* XXX check for overflow */
			bp += n;		/* returned len includes EOS */

			/* "Find first satisfactory answer" */
			nr->hostent = he;
			nr->ttl = rttl;
			return (1);
		}
	}

	nr->hostent = he;
	nr->ttl = rttl;
	return (1);
}
