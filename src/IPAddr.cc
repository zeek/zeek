// See the file "COPYING" in the main distribution directory for copyright.

#include <string>
#include <vector>
#include "IPAddr.h"
#include "Reporter.h"

const uint8_t IPAddr::v4_mapped_prefix[12] = { 0, 0, 0, 0,
                                               0, 0, 0, 0,
                                               0, 0, 0xff, 0xff };

void IPAddr::Mask(int top_bits_to_keep)
	{
	if ( top_bits_to_keep <= 0 || top_bits_to_keep > 128 )
		{
		reporter->Error("Bad IPAddr::Mask value %d", top_bits_to_keep);
		return;
		}

	uint32_t tmp[4];
	memcpy(tmp, in6.s6_addr, sizeof(in6.s6_addr));

	int word = 3;
	int bits_to_chop = 128 - top_bits_to_keep;

	while ( bits_to_chop >= 32 )
		{
		tmp[word] = 0;
		--word;
		bits_to_chop -= 32;
		}

	uint32_t w = ntohl(tmp[word]);
	w >>= bits_to_chop;
	w <<= bits_to_chop;
	tmp[word] = htonl(w);

	memcpy(in6.s6_addr, tmp, sizeof(in6.s6_addr));
	}

void IPAddr::ReverseMask(int top_bits_to_chop)
	{
	if ( top_bits_to_chop <= 0 || top_bits_to_chop > 128 )
		{
		reporter->Error("Bad IPAddr::ReverseMask value %d", top_bits_to_chop);
		return;
		}

	uint32_t tmp[4];
	memcpy(tmp, in6.s6_addr, sizeof(in6.s6_addr));

	int word = 0;
	int bits_to_chop = top_bits_to_chop;

	while ( bits_to_chop >= 32 )
		{
		tmp[word] = 0;
		++word;
		bits_to_chop -= 32;
		}

	uint32_t w = ntohl(tmp[word]);
	w <<= bits_to_chop;
	w >>= bits_to_chop;
	tmp[word] = htonl(w);

	memcpy(in6.s6_addr, tmp, sizeof(in6.s6_addr));
	}

void IPAddr::Init(const std::string& s)
	{
	if ( s.find(':') == std::string::npos ) // IPv4.
		{
		memcpy(in6.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));

		// parse the address directly instead of using inet_pton since
		// some platforms have more sensitive implementations than others
		// that can't e.g. handle leading zeroes.
		int a[4];
		int n = sscanf(s.c_str(), "%d.%d.%d.%d", a+0, a+1, a+2, a+3);
		if ( n != 4 || a[0] < 0 || a[1] < 0 || a[2] < 0 || a[3] < 0 ||
		     a[0] > 255 || a[1] > 255 || a[2] > 255 || a[3] > 255 )
			{
			reporter->Error("Bad IP address: %s", s.c_str());
			memset(in6.s6_addr, 0, sizeof(in6.s6_addr));
			return;
			}
		uint32_t addr = (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
		addr = htonl(addr);
		memcpy(&in6.s6_addr[12], &addr, sizeof(uint32_t));
		}

	else
		{
		if ( inet_pton(AF_INET6, s.c_str(), in6.s6_addr) <=0 )
			{
			reporter->Error("Bad IP address: %s", s.c_str());
			memset(in6.s6_addr, 0, sizeof(in6.s6_addr));
			}
		}
	}

string IPAddr::AsString() const
	{
	if ( GetFamily() == IPv4 )
		{
		char s[INET_ADDRSTRLEN];

		if ( inet_ntop(AF_INET, &in6.s6_addr[12], s, INET_ADDRSTRLEN) == NULL )
			return "<bad IPv4 address conversion";
		else
			return s;
		}
	else
		{
		char s[INET6_ADDRSTRLEN];

		if ( inet_ntop(AF_INET6, in6.s6_addr, s, INET6_ADDRSTRLEN) == NULL )
			return "<bad IPv6 address conversion";
		else
			return s;
		}
	}

IPPrefix::IPPrefix(const in4_addr& in4, uint8_t length)
	: prefix(in4), length(96 + length)
	{
	if ( length > 32 )
		reporter->InternalError("Bad in4_addr IPPrefix length : %d", length);

	prefix.Mask(this->length);
	}

IPPrefix::IPPrefix(const in6_addr& in6, uint8_t length)
	: prefix(in6), length(length)
	{
	if ( length > 128 )
		reporter->InternalError("Bad in6_addr IPPrefix length : %d", length);

	prefix.Mask(this->length);
	}

IPPrefix::IPPrefix(const IPAddr& addr, uint8_t length)
	: prefix(addr)
	{
	if ( prefix.GetFamily() == IPAddr::IPv4 )
		{
		if ( length > 32 )
			reporter->InternalError("Bad IPAddr(v4) IPPrefix length : %d",
			                        length);

		this->length = length + 96;
		}

	else
		{
		if ( length > 128 )
			reporter->InternalError("Bad IPAddr(v6) IPPrefix length : %d",
			                        length);

		this->length = length;
		}

	prefix.Mask(this->length);
	}

string IPPrefix::AsString() const
	{
	char l[16];

	if ( prefix.GetFamily() == IPAddr::IPv4 )
		modp_uitoa10(length - 96, l);
	else
		modp_uitoa10(length, l);

	return prefix.AsString() +"/" + l;
	}

