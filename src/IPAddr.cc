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

std::string IPAddr::CanonIPv4(const std::string& input)
	{
	vector<string> parts;
	string output;
	size_t start = 0;
	size_t end;

	do
		{
		end = input.find('.', start);
		string p;
		bool in_leading_zeroes = true;
		for ( size_t i = start; i != end && i < input.size(); ++i )
			{
			if ( in_leading_zeroes && input[i] == '0' ) continue;
			in_leading_zeroes = false;
			p.push_back(input[i]);
			}

		if ( p.size() == 0 )
			p.push_back('0');
		parts.push_back(p);
		start = end + 1;
		} while ( end != string::npos );

	for ( size_t i = 0; i < parts.size(); ++i )
		{
		if ( i > 0 )
			output += '.';
		output += parts[i];
		}

	return output;
	}

void IPAddr::Init(const std::string& s)
	{
	if ( s.find(':') == std::string::npos ) // IPv4.
		{
		memcpy(in6.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));

		if ( inet_pton(AF_INET, CanonIPv4(s).c_str(), &in6.s6_addr[12]) <=0 )
			{
			reporter->Error("Bad IP address: %s", s.c_str());
			memset(in6.s6_addr, 0, sizeof(in6.s6_addr));
			}
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

