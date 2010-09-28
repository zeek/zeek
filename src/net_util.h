// $Id: net_util.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef netutil_h
#define netutil_h

#include "config.h"

#include <assert.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>

#ifdef LINUX
	/* sigh */
#define source uh_sport 
#define dest uh_dport 
#define len uh_ulen   
#define check uh_sum
#endif

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "util.h"

#ifdef HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#else
struct ip6_hdr {
	uint16		ip6_plen;
	uint8		ip6_nxt;
	uint8		ip6_hlim;
};
#endif

#include "util.h"

#ifdef BROv6
typedef uint32* addr_type;	// a pointer to 4 uint32's
typedef const uint32* const_addr_type;
#define NUM_ADDR_WORDS 4

typedef struct {
	uint32 net[4];
	uint32 width;
} subnet_type;

#else
typedef uint32 addr_type;
typedef const uint32 const_addr_type;
#define NUM_ADDR_WORDS 1

typedef struct {
	uint32 net;
	uint32 width;
} subnet_type;

#endif

// For Solaris.
#if !defined(TCPOPT_WINDOW) && defined(TCPOPT_WSCALE)
#define	TCPOPT_WINDOW TCPOPT_WSCALE
#endif

#if !defined(TCPOPT_TIMESTAMP) && defined(TCPOPT_TSTAMP)
#define	TCPOPT_TIMESTAMP TCPOPT_TSTAMP
#endif

// True if sequence # a is between b and c (b <= a <= c).  It must be true
// that b <= c in the sequence space.
inline int seq_between(uint32 a, uint32 b, uint32 c)
	{
	if ( b <= c )
		return a >= b && a <= c;
	else
		return a >= b || a <= c;
	}

// Returns a - b, adjusted for sequence wraparound.
inline int seq_delta(uint32 a, uint32 b)
	{
	return int(a-b);
	}

// Returns the ones-complement checksum of a chunk of b short-aligned bytes.
extern int ones_complement_checksum(const void* p, int b, uint32 sum);

extern int tcp_checksum(const struct ip* ip, const struct tcphdr* tp, int len);
extern int udp_checksum(const struct ip* ip, const struct udphdr* up, int len);
#ifdef BROv6
extern int udp6_checksum(const struct ip6_hdr* ip, const struct udphdr* up,
				int len);
#endif
extern int icmp_checksum(const struct icmp* icmpp, int len);

// Given an address in host order, returns its "classical network prefix",
// also in host order.
extern uint32 addr_to_net(uint32 addr);
// Returns 'A', 'B', 'C' or 'D'
extern char addr_to_class(uint32 addr);

// Returns a pointer to static storage giving the ASCII dotted representation
// of the given address, which should be passed in network order.
extern const char* dotted_addr(uint32 addr, int alternative=0);
extern const char* dotted_addr(const uint32* addr, int alternative=0);

// Same, but for the network prefix.
extern const char* dotted_net(uint32 addr);
extern const char* dotted_net6(const uint32* addr);

// Given an ASCII dotted representation, returns the corresponding address
// in network order.
extern uint32 dotted_to_addr(const char* addr_text);
extern uint32* dotted_to_addr6(const char* addr_text);

extern int is_v4_addr(const uint32 addr[4]);
extern uint32 to_v4_addr(const uint32* addr);

extern uint32 mask_addr(uint32 a, uint32 top_bits_to_keep);
extern const uint32* mask_addr(const uint32* a, uint32 top_bits_to_keep);

extern const char* fmt_conn_id(const uint32* src_addr, uint32 src_port,
				const uint32* dst_addr, uint32 dst_port);

inline void copy_addr(const uint32* src_a, uint32* dst_a)
	{
#ifdef BROv6
	dst_a[0] = src_a[0];
	dst_a[1] = src_a[1];
	dst_a[2] = src_a[2];
	dst_a[3] = src_a[3];
#else
	dst_a[0] = src_a[0];
#endif
	}

inline int addr_eq(const uint32* a1, const uint32* a2)
	{
#ifdef BROv6
	return a1[0] == a2[0] &&
		a1[1] == a2[1] &&
		a1[2] == a2[2] &&
		a1[3] == a2[3];
#else
	return a1[0] == a2[0];
#endif
	}

inline int subnet_eq(const subnet_type* s1, const subnet_type* s2)
	{
#ifdef BROv6
	return s1->net[0] == s2->net[0] &&
		s1->net[1] == s2->net[1] &&
		s1->net[2] == s2->net[2] &&
		s1->net[3] == s2->net[3] &&
		s1->width == s2->width;
#else
	return s1->net == s2->net && s1->width == s2->width;
#endif
	}

// Read 4 bytes from data and return in network order.
extern uint32 extract_uint32(const u_char* data);

// Endian conversions for double.
// This is certainly not a very clean solution but should work on the
// major platforms. Alternativly, we could use a string format or the
// XDR library.

#ifdef WORDS_BIGENDIAN

inline double ntohd(double d)	{ return d; }
inline double htond(double d)	{ return d; }

#else

inline double ntohd(double d)
	{
	assert(sizeof(d) == 8);

	double tmp;
	char* src = (char*) &d;
	char* dst = (char*) &tmp;

	dst[0] = src[7];
	dst[1] = src[6];
	dst[2] = src[5];
	dst[3] = src[4];
	dst[4] = src[3];
	dst[5] = src[2];
	dst[6] = src[1];
	dst[7] = src[0];

	return tmp;
	}

inline double htond(double d) { return ntohd(d); }

#endif

#endif
