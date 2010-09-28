// $Id: net_util.cc 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#ifdef BROv6
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#endif

#include "net_util.h"

// - adapted from tcpdump
// Returns the ones-complement checksum of a chunk of b short-aligned bytes.
int ones_complement_checksum(const void* p, int b, uint32 sum)
	{
	const u_short* sp = (u_short*) p;	// better be aligned!

	b /= 2;	// convert to count of short's

	/* No need for endian conversions. */
	while ( --b >= 0 )
		sum += *sp++;

	while ( sum > 0xffff )
		sum = (sum & 0xffff) + (sum >> 16);

	return sum;
	}

int tcp_checksum(const struct ip* ip, const struct tcphdr* tp, int len)
	{
	// ### Note, this is only correct for IPv4.  This routine is only
	// used by the connection compressor (which we turn off for IPv6
	// traffic) and trace rewriting (which currently doesn't support
	// IPv6 either).

	int tcp_len = tp->th_off * 4 + len;
	uint32 sum;

	if ( len % 2 == 1 )
		// Add in pad byte.
		sum = htons(((const u_char*) tp)[tcp_len - 1] << 8);
	else
		sum = 0;

	sum = ones_complement_checksum((void*) &ip->ip_src.s_addr, 4, sum);
	sum = ones_complement_checksum((void*) &ip->ip_dst.s_addr, 4, sum);

	uint32 addl_pseudo =
		(htons(IPPROTO_TCP) << 16) | htons((unsigned short) tcp_len);

	sum = ones_complement_checksum((void*) &addl_pseudo, 4, sum);
	sum = ones_complement_checksum((void*) tp, tcp_len, sum);

	return sum;
	}

int udp_checksum(const struct ip* ip, const struct udphdr* up, int len)
	{
	uint32 sum;

	if ( len % 2 == 1 )
		// Add in pad byte.
		sum = htons(((const u_char*) up)[len - 1] << 8);
	else
		sum = 0;

	sum = ones_complement_checksum((void*) &ip->ip_src.s_addr, 4, sum);
	sum = ones_complement_checksum((void*) &ip->ip_dst.s_addr, 4, sum);

	uint32 addl_pseudo =
		(htons(IPPROTO_UDP) << 16) | htons((unsigned short) len);

	sum = ones_complement_checksum((void*) &addl_pseudo, 4, sum);
	sum = ones_complement_checksum((void*) up, len, sum);

	return sum;
	}

#ifdef BROv6
int udp6_checksum(const struct ip6_hdr* ip6, const struct udphdr* up, int len)
	{
	uint32 sum;

	if ( len % 2 == 1 )
		// Add in pad byte.
		sum = htons(((const u_char*) up)[len - 1] << 8);
	else
		sum = 0;

	sum = ones_complement_checksum((void*) ip6->ip6_src.s6_addr, 16, sum);
	sum = ones_complement_checksum((void*) ip6->ip6_dst.s6_addr, 16, sum);

	sum = ones_complement_checksum((void*) &len, 4, sum);
	uint32 addl_pseudo = htons(IPPROTO_UDP);
	sum = ones_complement_checksum((void*) &addl_pseudo, 4, sum);
	sum = ones_complement_checksum((void*) up, len, sum);

	return sum;
	}
#endif

int icmp_checksum(const struct icmp* icmpp, int len)
	{
	uint32 sum;

	if ( len % 2 == 1 )
		// Add in pad byte.
		sum = htons(((const u_char*) icmpp)[len - 1] << 8);
	else
		sum = 0;

	sum = ones_complement_checksum((void*) icmpp, len, sum);

	return sum;
	}


#define CLASS_A 0x00000000
#define CLASS_B 0x80000000
#define CLASS_C 0xc0000000
#define CLASS_D 0xe0000000
#define CLASS_E 0xf0000000

#define CHECK_CLASS(addr,class) (((addr) & (class)) == (class))
char addr_to_class(uint32 addr)
	{
	if ( CHECK_CLASS(addr, CLASS_E) )
		return 'E';
	else if ( CHECK_CLASS(addr, CLASS_D) )
		return 'D';
	else if ( CHECK_CLASS(addr, CLASS_C) )
		return 'C';
	else if ( CHECK_CLASS(addr, CLASS_B) )
		return 'B';
	else
		return 'A';
	}

uint32 addr_to_net(uint32 addr)
	{
	if ( CHECK_CLASS(addr, CLASS_D) )
		; // class D's are left alone ###
	else if ( CHECK_CLASS(addr, CLASS_C) )
		addr = addr & 0xffffff00;
	else if ( CHECK_CLASS(addr, CLASS_B) )
		addr = addr & 0xffff0000;
	else
		addr = addr & 0xff000000;

	return addr;
	}

const char* dotted_addr(uint32 addr, int alternative)
	{
	addr = ntohl(addr);
	const char* fmt = alternative ? "%d,%d.%d.%d" : "%d.%d.%d.%d";

	static char buf[32];
	snprintf(buf, sizeof(buf), fmt,
		addr >> 24, (addr >> 16) & 0xff,
		(addr >> 8) & 0xff, addr & 0xff);

	return buf;
	}

const char* dotted_addr(const uint32* addr, int alternative)
	{
#ifdef BROv6
	if ( is_v4_addr(addr) )
		return dotted_addr(addr[3], alternative);

	static char buf[256];

	if ( inet_ntop(AF_INET6, addr, buf, sizeof buf) == NULL )
		return "<bad IPv6 address conversion>";

	return buf;

#else
	return dotted_addr(to_v4_addr(addr), alternative);
#endif
	}

const char* dotted_net(uint32 addr)
	{
	addr = ntohl(addr);

	static char buf[32];

	if ( CHECK_CLASS(addr, CLASS_D) )
		sprintf(buf, "%d.%d.%d.%d",
			addr >> 24, (addr >> 16) & 0xff,
			(addr >> 8) & 0xff, addr & 0xff);

	else if ( CHECK_CLASS(addr, CLASS_C) )
		sprintf(buf, "%d.%d.%d",
			addr >> 24, (addr >> 16) & 0xff, (addr >> 8) & 0xff);

	else
		// Same for class A's and B's.
		sprintf(buf, "%d.%d", addr >> 24, (addr >> 16) & 0xff);

	return buf;
	}

#ifdef BROv6
const char* dotted_net6(const uint32* addr)
	{
	if ( is_v4_addr(addr) )
		return dotted_net(to_v4_addr(addr));
	else
		// ### this isn't right, but net's should go away eventually ...
		return dotted_addr(addr);
	}
#endif

uint32 dotted_to_addr(const char* addr_text)
	{
	int addr[4];

	if ( sscanf(addr_text,
		    "%d.%d.%d.%d", addr+0, addr+1, addr+2, addr+3) != 4 )
		{
		error("bad dotted address:", addr_text );
		return 0;
		}

	if ( addr[0] < 0 || addr[1] < 0 || addr[2] < 0 || addr[3] < 0 ||
	     addr[0] > 255 || addr[1] > 255 || addr[2] > 255 || addr[3] > 255 )
		{
		error("bad dotted address:", addr_text);
		return 0;
		}

	uint32 a = (addr[0] << 24) | (addr[1] << 16) | (addr[2] << 8) | addr[3];

	// ### perhaps do gethostbyaddr here?

	return uint32(htonl(a));
	}

#ifdef BROv6
uint32* dotted_to_addr6(const char* addr_text)
	{
	uint32* addr = new uint32[4];
	if ( inet_pton(AF_INET6, addr_text, addr) <= 0 )
		{
		error("bad IPv6 address:", addr_text );
		addr[0] = addr[1] = addr[2] = addr[3] = 0;
		}

	return addr;
	}

#endif

#ifdef BROv6
int is_v4_addr(const uint32 addr[4])
	{
	return addr[0] == 0 && addr[1] == 0 && addr[2] == 0;
	}
#endif

uint32 to_v4_addr(const uint32* addr)
	{
#ifdef BROv6
	if ( ! is_v4_addr(addr) )
		internal_error("conversion of non-IPv4 address to IPv4 address");
	return addr[3];
#else
	return addr[0];
#endif
	}

uint32 mask_addr(uint32 a, uint32 top_bits_to_keep)
	{
	if ( top_bits_to_keep > 32 )
		{
		error("bad address mask value", top_bits_to_keep);
		return a;
		}

	if ( top_bits_to_keep == 0 )
		// The shifts below don't have any effect with 0, i.e.,
		// 1 << 32 does not yield 0; either due to compiler
		// misoptimization or language semantics.
		return 0;

	uint32 addr = ntohl(a);

	int shift = 32 - top_bits_to_keep;
	addr >>= shift;
	addr <<= shift;

	return htonl(addr);
	}

const uint32* mask_addr(const uint32* a, uint32 top_bits_to_keep)
	{
#ifdef BROv6
	static uint32 addr[4];

	addr[0] = a[0];
	addr[1] = a[1];
	addr[2] = a[2];
	addr[3] = a[3];

	// This is a bit dicey: if it's a v4 address, then we interpret
	// the mask as being with respect to 32 bits total, even though
	// strictly speaking, the v4 address comprises the least-significant
	// bits out of 128, rather than the most significant.  However,
	// we only do this if the mask itself is consistent for a 32-bit
	// address.
	uint32 max_bits = (is_v4_addr(a) && top_bits_to_keep <= 32) ? 32 : 128;

	if ( top_bits_to_keep == 0 || top_bits_to_keep > max_bits )
		{
		error("bad address mask value", top_bits_to_keep);
		return addr;
		}

	int word = 3;	// start zeroing out with word #3
	int bits_to_chop = max_bits - top_bits_to_keep;	// bits to discard
	while ( bits_to_chop >= 32 )
		{ // there's an entire word to discard
		addr[word] = 0;
		--word;	// move on to next, more significant word
		bits_to_chop -= 32;	// we just go rid of 32 bits
		}

	// All that's left to work with now is the word pointed to by "word".
	uint32 addr32 = ntohl(addr[word]);
	addr32 >>= bits_to_chop;
	addr32 <<= bits_to_chop;
	addr[word] = htonl(addr32);

	return addr;
#else
	return a;
#endif
	}

const char* fmt_conn_id(const uint32* src_addr, uint32 src_port,
			const uint32* dst_addr, uint32 dst_port)
	{
	char addr1[128], addr2[128];
	static char buffer[512];

	strcpy(addr1, dotted_addr(src_addr));
	strcpy(addr2, dotted_addr(dst_addr));

	safe_snprintf(buffer, sizeof(buffer), "%s:%d > %s:%d",
			addr1, src_port, addr2, dst_port);

	return buffer;
	}

uint32 extract_uint32(const u_char* data)
	{
	uint32 val;

	val = data[0] << 24;
	val |= data[1] << 16;
	val |= data[2] << 8;
	val |= data[3];

	return val;
	}
