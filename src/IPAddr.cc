// See the file "COPYING" in the main distribution directory for copyright.

#include <cstdlib>
#include <string>
#include <vector>
#include "IPAddr.h"
#include "Reporter.h"
#include "Conn.h"
#include "bro_inet_ntop.h"

#include "analyzer/Manager.h"

const uint8_t IPAddr::v4_mapped_prefix[12] = { 0, 0, 0, 0,
                                               0, 0, 0, 0,
                                               0, 0, 0xff, 0xff };

ConnIDKey BuildConnIDKey(const ConnID& id)
	{
	ConnIDKey key;

	// Lookup up connection based on canonical ordering, which is
	// the smaller of <src addr, src port> and <dst addr, dst port>
	// followed by the other.
	if ( id.is_one_way ||
	     addr_port_canon_lt(id.src_addr, id.src_port, id.dst_addr, id.dst_port)
	   )
		{
		key.ip1 = id.src_addr.in6;
		key.ip2 = id.dst_addr.in6;
		key.port1 = id.src_port;
		key.port2 = id.dst_port;
		}
	else
		{
		key.ip1 = id.dst_addr.in6;
		key.ip2 = id.src_addr.in6;
		key.port1 = id.dst_port;
		key.port2 = id.src_port;
		}

	return key;
	}

static inline uint32_t bit_mask32(int bottom_bits)
	{
	if ( bottom_bits >= 32 )
		return 0xffffffff;

	return (((uint32_t) 1) << bottom_bits) - 1;
	}

void IPAddr::Mask(int top_bits_to_keep)
	{
	if ( top_bits_to_keep < 0 || top_bits_to_keep > 128 )
		{
		reporter->Error("Bad IPAddr::Mask value %d", top_bits_to_keep);
		return;
		}

	uint32_t mask_bits[4] = { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff };
	std::ldiv_t res = std::ldiv(top_bits_to_keep, 32);

	if ( res.quot < 4 )
		mask_bits[res.quot] =
		        htonl(mask_bits[res.quot] & ~bit_mask32(32 - res.rem));

	for ( unsigned int i = res.quot + 1; i < 4; ++i )
		mask_bits[i] = 0;

	uint32_t* p = reinterpret_cast<uint32_t*>(in6.s6_addr);

	for ( unsigned int i = 0; i < 4; ++i )
		p[i] &= mask_bits[i];
	}

void IPAddr::ReverseMask(int top_bits_to_chop)
	{
	if ( top_bits_to_chop < 0 || top_bits_to_chop > 128 )
		{
		reporter->Error("Bad IPAddr::ReverseMask value %d", top_bits_to_chop);
		return;
		}

	uint32_t mask_bits[4] = { 0, 0, 0, 0 };
	std::ldiv_t res = std::ldiv(top_bits_to_chop, 32);

	if ( res.quot < 4 )
		mask_bits[res.quot] = htonl(bit_mask32(32 - res.rem));

	for ( unsigned int i = res.quot + 1; i < 4; ++i )
		mask_bits[i] = 0xffffffff;

	uint32_t* p = reinterpret_cast<uint32_t*>(in6.s6_addr);

	for ( unsigned int i = 0; i < 4; ++i )
		p[i] &= mask_bits[i];
	}

bool IPAddr::ConvertString(const char* s, in6_addr* result)
	{
	for ( auto p = s; *p; ++p )
		if ( *p == ':' )
			// IPv6
			return (inet_pton(AF_INET6, s, result->s6_addr) == 1);

	// IPv4
	// Parse the address directly instead of using inet_pton since
	// some platforms have more sensitive implementations than others
	// that can't e.g. handle leading zeroes.
	int a[4];
	int n = 0;
	int match_count = sscanf(s, "%d.%d.%d.%d%n", a+0, a+1, a+2, a+3, &n);

	if ( match_count != 4 )
		return false;

	if ( s[n] != '\0' )
		return false;

	for ( auto i = 0; i < 4; ++i )
		if ( a[i] < 0 || a[i] > 255 )
			return false;

	uint32_t addr = (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
	addr = htonl(addr);
	memcpy(result->s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
	memcpy(&result->s6_addr[12], &addr, sizeof(uint32_t));
	return true;
	}

void IPAddr::Init(const char* s)
	{
	if ( ! ConvertString(s, &in6) )
		{
		reporter->Error("Bad IP address: %s", s);
		memset(in6.s6_addr, 0, sizeof(in6.s6_addr));
		}
	}

string IPAddr::AsString() const
	{
	if ( GetFamily() == IPv4 )
		{
		char s[INET_ADDRSTRLEN];

		if ( ! bro_inet_ntop(AF_INET, &in6.s6_addr[12], s, INET_ADDRSTRLEN) )
			return "<bad IPv4 address conversion";
		else
			return s;
		}
	else
		{
		char s[INET6_ADDRSTRLEN];

		if ( ! bro_inet_ntop(AF_INET6, in6.s6_addr, s, INET6_ADDRSTRLEN) )
			return "<bad IPv6 address conversion";
		else
			return s;
		}
	}

string IPAddr::AsHexString() const
	{
	char buf[33];

	if ( GetFamily() == IPv4 )
		{
		uint32_t* p = (uint32_t*) &in6.s6_addr[12];
		snprintf(buf, sizeof(buf), "%08x", (uint32_t) ntohl(*p));
		}
	else
		{
		uint32_t* p = (uint32_t*) in6.s6_addr;
		snprintf(buf, sizeof(buf), "%08x%08x%08x%08x",
				(uint32_t) ntohl(p[0]), (uint32_t) ntohl(p[1]),
				(uint32_t) ntohl(p[2]), (uint32_t) ntohl(p[3]));
		}

	return buf;
	}

string IPAddr::PtrName() const
	{
	if ( GetFamily() == IPv4 )
		{
		char buf[256];
		uint32_t* p = (uint32_t*) &in6.s6_addr[12];
		uint32_t a = ntohl(*p);
		uint32_t a3 = (a >> 24) & 0xff;
		uint32_t a2 = (a >> 16) & 0xff;
		uint32_t a1 = (a >> 8) & 0xff;
		uint32_t a0 = a & 0xff;
		snprintf(buf, sizeof(buf), "%u.%u.%u.%u.in-addr.arpa", a0, a1, a2, a3);
		return buf;
		}
	else
		{
		static const char hex_digit[] = "0123456789abcdef";
		string ptr_name("ip6.arpa");
		uint32_t* p = (uint32_t*) in6.s6_addr;

		for ( unsigned int i = 0; i < 4; ++i )
			{
			uint32_t a = ntohl(p[i]);
			for ( unsigned int j = 1; j <=8; ++j )
				{
				ptr_name.insert(0, 1, '.');
				ptr_name.insert(0, 1, hex_digit[(a >> (32-j*4)) & 0x0f]);
				}
			}

		return ptr_name;
		}
	}

IPPrefix::IPPrefix(const in4_addr& in4, uint8_t length)
	: prefix(in4), length(96 + length)
	{
	if ( length > 32 )
		{
		reporter->Error("Bad in4_addr IPPrefix length : %d", length);
		this->length = 0;
		}

	prefix.Mask(this->length);
	}

IPPrefix::IPPrefix(const in6_addr& in6, uint8_t length)
	: prefix(in6), length(length)
	{
	if ( length > 128 )
		{
		reporter->Error("Bad in6_addr IPPrefix length : %d", length);
		this->length = 0;
		}

	prefix.Mask(this->length);
	}

bool IPAddr::CheckPrefixLength(uint8_t length, bool len_is_v6_relative) const
	{
	if ( GetFamily() == IPv4 && ! len_is_v6_relative )
		{
		if ( length > 32 )
			return false;
		}

	else
		{
		if ( length > 128 )
			return false;
		}

	return true;
	}

IPPrefix::IPPrefix(const IPAddr& addr, uint8_t length, bool len_is_v6_relative)
	: prefix(addr)
	{
	if ( prefix.CheckPrefixLength(length, len_is_v6_relative) )
		{
		if ( prefix.GetFamily() == IPv4 && ! len_is_v6_relative )
			this->length = length + 96;
		else
			this->length = length;
		}
	else
		{
		auto vstr = prefix.GetFamily() == IPv4 ? "v4" : "v6";
		reporter->Error("Bad IPAddr(%s) IPPrefix length : %d", vstr, length);
		this->length = 0;
		}

	prefix.Mask(this->length);
	}

string IPPrefix::AsString() const
	{
	char l[16];

	if ( prefix.GetFamily() == IPv4 )
		modp_uitoa10(length - 96, l);
	else
		modp_uitoa10(length, l);

	return prefix.AsString() +"/" + l;
	}

bool IPPrefix::ConvertString(const char* text, IPPrefix* result)
	{
	string s(text);
	size_t slash_loc = s.find('/');

	if ( slash_loc == string::npos )
		return false;

	auto ip_str = s.substr(0, slash_loc);
	auto len = atoi(s.substr(slash_loc + 1).data());

	in6_addr tmp;

	if ( ! IPAddr::ConvertString(ip_str.data(), &tmp) )
		return false;

	auto ip = IPAddr(tmp);

	if ( ! ip.CheckPrefixLength(len) )
		return false;

	*result = IPPrefix(ip, len);
	return true;
	}
