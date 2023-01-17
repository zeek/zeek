// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h"

// Define first.
enum TransportProto
	{
	TRANSPORT_UNKNOWN,
	TRANSPORT_TCP,
	TRANSPORT_UDP,
	TRANSPORT_ICMP,
	};

extern const char* transport_proto_string(TransportProto proto);

enum IPFamily
	{
	IPv4,
	IPv6
	};

// Force these files to stay in this order. Normally, clang-format
// wants to move sys/types.h to the end of this block, but that
// breaks FreeBSD builds.
// clang-format off
#include <sys/types.h>
#include <arpa/inet.h>
#include <cassert>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
// clang-format on
#ifdef HAVE_LINUX
#define __FAVOR_BSD
#endif
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "zeek/util.h"

#ifdef HAVE_NETINET_IP6_H
#include <netinet/ip6.h>

#ifndef HAVE_IP6_OPT
struct ip6_opt
	{
	uint8_t ip6o_type;
	uint8_t ip6o_len;
	};
#endif // HAVE_IP6_OPT

#ifndef HAVE_IP6_EXT
struct ip6_ext
	{
	uint8_t ip6e_nxt;
	uint8_t ip6e_len;
	};
#endif // HAVE_IP6_EXT

#else

struct ip6_hdr
	{
		union {
		struct ip6_hdrctl
			{
			uint32_t ip6_un1_flow; /* 4 bits version, 8 bits TC, 20 bits
			                          flow-ID */
			uint16_t ip6_un1_plen; /* payload length */
			uint8_t ip6_un1_nxt; /* next header */
			uint8_t ip6_un1_hlim; /* hop limit */
			} ip6_un1;
		uint8_t ip6_un2_vfc; /* 4 bits version, top 4 bits tclass */
		} ip6_ctlun;
	struct in6_addr ip6_src; /* source address */
	struct in6_addr ip6_dst; /* destination address */
	};

#define ip6_vfc ip6_ctlun.ip6_un2_vfc
#define ip6_flow ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops ip6_ctlun.ip6_un1.ip6_un1_hlim

struct ip6_opt
	{
	uint8_t ip6o_type;
	uint8_t ip6o_len;
	};

struct ip6_ext
	{
	uint8_t ip6e_nxt;
	uint8_t ip6e_len;
	};

struct ip6_frag
	{
	uint8_t ip6f_nxt; /* next header */
	uint8_t ip6f_reserved; /* reserved field */
	uint16_t ip6f_offlg; /* offset, reserved, and flag */
	uint32_t ip6f_ident; /* identification */
	};

struct ip6_hbh
	{
	uint8_t ip6h_nxt; /* next header */
	uint8_t ip6h_len; /* length in units of 8 octets */
	/* followed by options */
	};

struct ip6_dest
	{
	uint8_t ip6d_nxt; /* next header */
	uint8_t ip6d_len; /* length in units of 8 octets */
	/* followed by options */
	};

struct ip6_rthdr
	{
	uint8_t ip6r_nxt; /* next header */
	uint8_t ip6r_len; /* length in units of 8 octets */
	uint8_t ip6r_type; /* routing type */
	uint8_t ip6r_segleft; /* segments left */
	/* followed by routing type specific data */
	};
#endif // HAVE_NETINET_IP6_H

// For Solaris.
#if ! defined(TCPOPT_WINDOW) && defined(TCPOPT_WSCALE)
#define TCPOPT_WINDOW TCPOPT_WSCALE
#endif

#if ! defined(TCPOPT_TIMESTAMP) && defined(TCPOPT_TSTAMP)
#define TCPOPT_TIMESTAMP TCPOPT_TSTAMP
#endif

namespace zeek
	{

class IPAddr;
class IP_Hdr;

namespace detail
	{

struct checksum_block
	{
	const uint8_t* block;
	int len;
	};

struct ipv4_pseudo_hdr
	{
	in_addr src;
	in_addr dst;
	uint8_t zero;
	uint8_t next_proto;
	uint16_t len;
	};

struct ipv6_pseudo_hdr
	{
	in6_addr src;
	in6_addr dst;
	uint32_t len;
	uint8_t zero[3];
	uint8_t next_proto;
	};

extern uint16_t in_cksum(const checksum_block* blocks, int num_blocks);

inline uint16_t in_cksum(const uint8_t* data, int len)
	{
	checksum_block cb{data, len};
	return in_cksum(&cb, 1);
	}

extern uint16_t ip4_in_cksum(const IPAddr& src, const IPAddr& dst, uint8_t next_proto,
                             const uint8_t* data, int len);

extern uint16_t ip6_in_cksum(const IPAddr& src, const IPAddr& dst, uint8_t next_proto,
                             const uint8_t* data, int len);

inline uint16_t ip_in_cksum(bool is_ipv4, const IPAddr& src, const IPAddr& dst, uint8_t next_proto,
                            const uint8_t* data, int len)
	{
	if ( is_ipv4 )
		return ip4_in_cksum(src, dst, next_proto, data, len);
	return ip6_in_cksum(src, dst, next_proto, data, len);
	}

	} // namespace zeek::detail

// Returns the ones-complement checksum of a chunk of 'b' bytes.
extern int ones_complement_checksum(const void* p, int b, uint32_t sum);

extern int ones_complement_checksum(const IPAddr& a, uint32_t sum);

extern int icmp6_checksum(const struct icmp* icmpp, const IP_Hdr* ip, int len);
extern int icmp_checksum(const struct icmp* icmpp, int len);

extern int mobility_header_checksum(const IP_Hdr* ip);

// True if sequence # a is between b and c (b <= a <= c).  It must be true
// that b <= c in the sequence space.
inline bool seq_between(uint32_t a, uint32_t b, uint32_t c)
	{
	if ( b <= c )
		return a >= b && a <= c;
	else
		return a >= b || a <= c;
	}

// Returns a - b, adjusted for sequence wraparound.
inline int32_t seq_delta(uint32_t a, uint32_t b)
	{
	return a - b;
	}

// Returns 'A', 'B', 'C' or 'D'
extern char addr_to_class(uint32_t addr);

extern const char* fmt_conn_id(const IPAddr& src_addr, uint32_t src_port, const IPAddr& dst_addr,
                               uint32_t dst_port);
extern const char* fmt_conn_id(const uint32_t* src_addr, uint32_t src_port,
                               const uint32_t* dst_addr, uint32_t dst_port);

/**
 * Given a MAC address, formats it in hex as 00:de:ad:be:ef.
 * Supports both EUI-48 and EUI-64. If it's neither, returns
 * an empty string.
 *
 * @param m EUI-48 or EUI-64 MAC address to format, as a char array
 * @param len Number of bytes valid starting at *n*. This must be at
 *            least 8 for a valid address.
 * @return A string of the formatted MAC. Passes ownership to caller.
 */
extern std::string fmt_mac(const unsigned char* m, int len);

// Read 4 bytes from data and return in network order.
extern uint32_t extract_uint32(const u_char* data);

// Endian conversions for double.
// This is certainly not a very clean solution but should work on the
// major platforms. Alternatively, we could use a string format or the
// XDR library.

#ifdef WORDS_BIGENDIAN

inline double ntohd(double d)
	{
	return d;
	}
inline double htond(double d)
	{
	return d;
	}

inline float ntohf(float f)
	{
	return f;
	}
inline float htonf(float f)
	{
	return f;
	}

#ifndef HAVE_BYTEORDER_64
inline uint64_t ntohll(uint64_t i)
	{
	return i;
	}
inline uint64_t htonll(uint64_t i)
	{
	return i;
	}
#endif

#else

inline double ntohd(double d)
	{
	assert(sizeof(d) == 8);

	double tmp;
	char* src = (char*)&d;
	char* dst = (char*)&tmp;

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

inline double htond(double d)
	{
	return ntohd(d);
	}

inline float ntohf(float f)
	{
	assert(sizeof(f) == 4);

	float tmp;
	char* src = (char*)&f;
	char* dst = (char*)&tmp;

	dst[0] = src[3];
	dst[1] = src[2];
	dst[2] = src[1];
	dst[3] = src[0];

	return tmp;
	}

inline float htonf(float f)
	{
	return ntohf(f);
	}

#ifndef HAVE_BYTEORDER_64
inline uint64_t ntohll(uint64_t i)
	{
	u_char c;
		union {
		uint64_t i;
		u_char c[8];
		} x;

	x.i = i;
	c = x.c[0];
	x.c[0] = x.c[7];
	x.c[7] = c;
	c = x.c[1];
	x.c[1] = x.c[6];
	x.c[6] = c;
	c = x.c[2];
	x.c[2] = x.c[5];
	x.c[5] = c;
	c = x.c[3];
	x.c[3] = x.c[4];
	x.c[4] = c;
	return x.i;
	}

inline uint64_t htonll(uint64_t i)
	{
	return ntohll(i);
	}
#endif

#endif

	} // namespace zeek
