#include "IPAddr.h"
#include "Reporter.h"
#include "modp_numtoa.h"
#include <arpa/inet.h>

const uint8_t IPAddr::v4_mapped_prefix[12] = { 0, 0, 0, 0,
                                               0, 0, 0, 0,
                                               0, 0, 0xff, 0xff };

IPAddr::IPAddr()
	{
	memset(in6.s6_addr, 0, sizeof(in6.s6_addr));
	}

IPAddr::IPAddr(const in4_addr& in4)
	{
	memcpy(in6.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
	memcpy(&in6.s6_addr[12], &in4.s_addr, sizeof(in4.s_addr));
	}

IPAddr::IPAddr(const in6_addr& arg_in6)
	: in6(arg_in6)
	{
	}

void IPAddr::Init(const std::string& s)
	{
	if ( s.find(':') == std::string::npos ) //IPv4
		{
		memcpy(in6.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
		if ( inet_pton(AF_INET, s.c_str(), &in6.s6_addr[12]) <=0 )
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

IPAddr::IPAddr(const std::string& s)
	{
	Init(s);
	}

IPAddr::IPAddr(const BroString& s)
	{
	Init(s.CheckString());
	}

IPAddr::IPAddr(Family family, const uint32_t* bytes, ByteOrder order)
	{
	if ( family == IPv4 )
		{
		memcpy(in6.s6_addr, v4_mapped_prefix, sizeof(v4_mapped_prefix));
		memcpy(&in6.s6_addr[12], bytes, sizeof(uint32_t));
		if ( order == Host )
			{
			uint32_t* p = (uint32_t*) &in6.s6_addr[12];
			*p = htonl(*p);
			}
		}
	else
		{
		memcpy(in6.s6_addr, bytes, sizeof(in6.s6_addr));
		if ( order == Host )
			{
			for ( unsigned int i = 0; i < 4; ++ i)
				{
				uint32_t* p = (uint32_t*) &in6.s6_addr[i*4];
				*p = htonl(*p);
				}
			}
		}
	}

IPAddr::IPAddr(const IPAddr& other)
	{
	in6 = other.in6;
	}

IPAddr::~IPAddr()
	{
	}

IPAddr::Family IPAddr::family() const
	{
	if ( memcmp(in6.s6_addr, v4_mapped_prefix, 12) == 0 )
		return IPv4;
	else
		return IPv6;
	}

bool IPAddr::IsLoopback() const
	{
	if ( family() == IPv4 )
		return in6.s6_addr[12] == 127;
	else
		return ((in6.s6_addr[0] == 0) && (in6.s6_addr[1] == 0)
		     && (in6.s6_addr[2] == 0) && (in6.s6_addr[3] == 0)
		     && (in6.s6_addr[4] == 0) && (in6.s6_addr[5] == 0)
		     && (in6.s6_addr[6] == 0) && (in6.s6_addr[7] == 0)
		     && (in6.s6_addr[8] == 0) && (in6.s6_addr[9] == 0)
		     && (in6.s6_addr[10] == 0) && (in6.s6_addr[11] == 0)
		     && (in6.s6_addr[12] == 0) && (in6.s6_addr[13] == 0)
		     && (in6.s6_addr[14] == 0) && (in6.s6_addr[15] == 1));
	}

bool IPAddr::IsMulticast() const
	{
	if ( family() == IPv4 )
		return in6.s6_addr[12] == 224;
	else
		return in6.s6_addr[0] == 0xff;
	}

bool IPAddr::IsBroadcast() const
	{
	if ( family() == IPv4 )
		return ((in6.s6_addr[12] == 0xff) && (in6.s6_addr[13] == 0xff)
		     && (in6.s6_addr[14] == 0xff) && (in6.s6_addr[15] == 0xff));
	else
		return false;
	}

int IPAddr::GetBytes(uint32_t** bytes)
	{
	if ( family() == IPv4 )
		{
		*bytes = (uint32_t*) &in6.s6_addr[12];
		return 1;
		}
	else
		{
		*bytes = (uint32_t*) in6.s6_addr;
		return 4;
		}
	}

int IPAddr::GetBytes(const uint32_t** bytes) const
	{
	if ( family() == IPv4 )
		{
		*bytes = (uint32_t*) &in6.s6_addr[12];
		return 1;
		}
	else
		{
		*bytes = (uint32_t*) in6.s6_addr;
		return 4;
		}
	}

void IPAddr::CopyIPv6(uint32_t* bytes) const
	{
	memcpy(bytes, in6.s6_addr, sizeof(in6.s6_addr));
	}

void IPAddr::Mask(int top_bits_to_keep)
	{
	if ( top_bits_to_keep <=0 || top_bits_to_keep > 128 )
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
	if ( top_bits_to_chop <=0 || top_bits_to_chop > 128 )
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

IPAddr& IPAddr::operator =(const IPAddr& other)
	{
	// No self-assignment check here because it's correct without it and
	// makes the common case faster.
	in6 = other.in6;
	return *this;
	}

IPAddr::operator std::string() const
	{
	if ( family() == IPv4 )
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
			return "<bad IPv64 address conversion";
		else
			return s;
		}
	}

bool operator ==(const IPAddr& addr1, const IPAddr& addr2)
	{
	return memcmp(&addr1.in6, &addr2.in6, sizeof(in6_addr)) == 0;
	}

bool operator !=(const IPAddr& addr1, const IPAddr& addr2)
	{
	return ! (addr1 == addr2);
	}

bool operator <(const IPAddr& addr1, const IPAddr& addr2)
	{
	return memcmp(&addr1.in6, &addr2.in6, sizeof(in6_addr)) < 0;
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
	if ( prefix.family() == IPAddr::IPv4 )
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

IPPrefix::IPPrefix(const std::string& s, uint8_t length)
	: prefix(s), length(length)
	{
	if ( prefix.family() == IPAddr::IPv4 && length > 32 )
		reporter->InternalError("Bad string IPPrefix length : %d", length);
	else if ( prefix.family() == IPAddr::IPv6 && length > 128 )
		reporter->InternalError("Bad string IPPrefix length : %d", length);
	prefix.Mask(this->length);
	}

IPPrefix::IPPrefix(const IPPrefix& other)
	: prefix(other.prefix), length(other.length)
	{
	}

IPPrefix::~IPPrefix()
	{
	}

const IPAddr& IPPrefix::Prefix() const
	{
	return prefix;
	}

uint8_t IPPrefix::Length() const
	{
	return prefix.family() == IPAddr::IPv4 ? length - 96 : length;
	}

uint8_t IPPrefix::LengthIPv6() const
	{
	return length;
	}

IPPrefix& IPPrefix::operator =(const IPPrefix& other)
	{
	// No self-assignment check here because it's correct without it and
	// makes the common case faster.
	prefix = other.Prefix();
	length = other.Length();
	return *this;
	}

IPPrefix::operator std::string() const
	{
	char l[16];
	if ( prefix.family() == IPAddr::IPv4 )
		modp_uitoa10(length - 96, l);
	else
		modp_uitoa10(length, l);
	return std::string(prefix).append("/").append(l);
	}

bool operator ==(const IPPrefix& net1, const IPPrefix& net2)
	{
	return net1.Prefix() == net2.Prefix() && net1.Length() == net2.Length();
	}

bool operator <(const IPPrefix& net1, const IPPrefix& net2)
	{
	if ( net1.Prefix() < net2.Prefix() )
		return true;
	else if ( net1.Prefix() == net2.Prefix() )
		return net1.Length() < net2.Length();
	else
		return false;
	}
