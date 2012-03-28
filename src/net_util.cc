// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include "Reporter.h"
#include "net_util.h"
#include "IPAddr.h"

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

int ones_complement_checksum(const IPAddr& a, uint32 sum)
	{
	const uint32* bytes;
	int len = a.GetBytes(&bytes);
	return ones_complement_checksum(bytes, len*4, sum);
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

	uint32 l = htonl(len);
	sum = ones_complement_checksum((void*) &l, 4, sum);

	uint32 addl_pseudo = htons(IPPROTO_UDP);
	sum = ones_complement_checksum((void*) &addl_pseudo, 4, sum);
	sum = ones_complement_checksum((void*) up, len, sum);

	return sum;
	}

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

const char* fmt_conn_id(const IPAddr& src_addr, uint32 src_port,
			const IPAddr& dst_addr, uint32 dst_port)
	{
	static char buffer[512];

	safe_snprintf(buffer, sizeof(buffer), "%s:%d > %s:%d",
			string(src_addr).c_str(), src_port,
			string(dst_addr).c_str(), dst_port);

	return buffer;
	}

const char* fmt_conn_id(const uint32* src_addr, uint32 src_port,
			const uint32* dst_addr, uint32 dst_port)
	{
	IPAddr src(IPAddr::IPv6, src_addr, IPAddr::Network);
	IPAddr dst(IPAddr::IPv6, dst_addr, IPAddr::Network);
	return fmt_conn_id(src, src_port, dst, dst_port);
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
