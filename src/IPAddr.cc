// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/IPAddr.h"

#include <cstdlib>
#include <string>
#include <vector>

#include "zeek/3rdparty/zeek_inet_ntop.h"
#include "zeek/Conn.h"
#include "zeek/Hash.h"
#include "zeek/Reporter.h"
#include "zeek/ZeekString.h"
#include "zeek/analyzer/Manager.h"

namespace zeek
	{

const IPAddr IPAddr::v4_unspecified = IPAddr(in4_addr{});
const IPAddr IPAddr::v6_unspecified = IPAddr();

namespace detail
	{

ConnKey::ConnKey(const IPAddr& src, const IPAddr& dst, uint16_t src_port, uint16_t dst_port,
                 TransportProto t, bool one_way)
	{
	Init(src, dst, src_port, dst_port, t, one_way);
	}

ConnKey::ConnKey(const ConnTuple& id)
	{
	Init(id.src_addr, id.dst_addr, id.src_port, id.dst_port, id.proto, id.is_one_way);
	}

ConnKey& ConnKey::operator=(const ConnKey& rhs)
	{
	if ( this == &rhs )
		return *this;

	// Because of padding in the object, this needs to memset to clear out
	// the extra memory used by padding. Otherwise, the session key stuff
	// doesn't work quite right.
	memset(this, 0, sizeof(ConnKey));

	memcpy(&ip1, &rhs.ip1, sizeof(in6_addr));
	memcpy(&ip2, &rhs.ip2, sizeof(in6_addr));
	port1 = rhs.port1;
	port2 = rhs.port2;
	transport = rhs.transport;
	valid = rhs.valid;

	return *this;
	}

ConnKey::ConnKey(Val* v)
	{
	const auto& vt = v->GetType();
	if ( ! IsRecord(vt->Tag()) )
		{
		valid = false;
		return;
		}

	RecordType* vr = vt->AsRecordType();
	auto vl = v->As<RecordVal*>();

	int orig_h, orig_p; // indices into record's value list
	int resp_h, resp_p;

	if ( vr == id::conn_id )
		{
		orig_h = 0;
		orig_p = 1;
		resp_h = 2;
		resp_p = 3;
		}
	else
		{
		// While it's not a conn_id, it may have equivalent fields.
		orig_h = vr->FieldOffset("orig_h");
		resp_h = vr->FieldOffset("resp_h");
		orig_p = vr->FieldOffset("orig_p");
		resp_p = vr->FieldOffset("resp_p");

		if ( orig_h < 0 || resp_h < 0 || orig_p < 0 || resp_p < 0 )
			{
			valid = false;
			return;
			}

		// ### we ought to check that the fields have the right
		// types, too.
		}

	const IPAddr& orig_addr = vl->GetFieldAs<AddrVal>(orig_h);
	const IPAddr& resp_addr = vl->GetFieldAs<AddrVal>(resp_h);

	auto orig_portv = vl->GetFieldAs<PortVal>(orig_p);
	auto resp_portv = vl->GetFieldAs<PortVal>(resp_p);

	Init(orig_addr, resp_addr, htons((unsigned short)orig_portv->Port()),
	     htons((unsigned short)resp_portv->Port()), orig_portv->PortType(), false);
	}

void ConnKey::Init(const IPAddr& src, const IPAddr& dst, uint16_t src_port, uint16_t dst_port,
                   TransportProto t, bool one_way)
	{
	// Because of padding in the object, this needs to memset to clear out
	// the extra memory used by padding. Otherwise, the session key stuff
	// doesn't work quite right.
	memset(this, 0, sizeof(ConnKey));

	// Lookup up connection based on canonical ordering, which is
	// the smaller of <src addr, src port> and <dst addr, dst port>
	// followed by the other.
	if ( one_way || addr_port_canon_lt(src, src_port, dst, dst_port) )
		{
		ip1 = src.in6;
		ip2 = dst.in6;
		port1 = src_port;
		port2 = dst_port;
		}
	else
		{
		ip1 = dst.in6;
		ip2 = src.in6;
		port1 = dst_port;
		port2 = src_port;
		}

	transport = t;
	valid = true;
	}

	} // namespace detail

IPAddr::IPAddr(const String& s)
	{
	Init(s.CheckString());
	}

std::unique_ptr<detail::HashKey> IPAddr::MakeHashKey() const
	{
	return std::make_unique<detail::HashKey>((void*)in6.s6_addr, sizeof(in6.s6_addr));
	}

static inline uint32_t bit_mask32(int bottom_bits)
	{
	if ( bottom_bits >= 32 )
		return 0xffffffff;

	return (((uint32_t)1) << bottom_bits) - 1;
	}

void IPAddr::Mask(int top_bits_to_keep)
	{
	if ( top_bits_to_keep < 0 || top_bits_to_keep > 128 )
		{
		reporter->Error("Bad IPAddr::Mask value %d", top_bits_to_keep);
		return;
		}

	uint32_t mask_bits[4] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
	std::ldiv_t res = std::ldiv(top_bits_to_keep, 32);

	if ( res.quot < 4 )
		mask_bits[res.quot] = htonl(mask_bits[res.quot] & ~bit_mask32(32 - res.rem));

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

	uint32_t mask_bits[4] = {0, 0, 0, 0};
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
	int match_count = sscanf(s, "%d.%d.%d.%d%n", a + 0, a + 1, a + 2, a + 3, &n);

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

std::string IPAddr::AsString() const
	{
	if ( GetFamily() == IPv4 )
		{
		char s[INET_ADDRSTRLEN];

		if ( ! zeek_inet_ntop(AF_INET, &in6.s6_addr[12], s, INET_ADDRSTRLEN) )
			return "<bad IPv4 address conversion";
		else
			return s;
		}
	else
		{
		char s[INET6_ADDRSTRLEN];

		if ( ! zeek_inet_ntop(AF_INET6, in6.s6_addr, s, INET6_ADDRSTRLEN) )
			return "<bad IPv6 address conversion";
		else
			return s;
		}
	}

std::string IPAddr::AsHexString() const
	{
	char buf[33];

	if ( GetFamily() == IPv4 )
		{
		uint32_t* p = (uint32_t*)&in6.s6_addr[12];
		snprintf(buf, sizeof(buf), "%08x", (uint32_t)ntohl(*p));
		}
	else
		{
		uint32_t* p = (uint32_t*)in6.s6_addr;
		snprintf(buf, sizeof(buf), "%08x%08x%08x%08x", (uint32_t)ntohl(p[0]), (uint32_t)ntohl(p[1]),
		         (uint32_t)ntohl(p[2]), (uint32_t)ntohl(p[3]));
		}

	return buf;
	}

std::string IPAddr::PtrName() const
	{
	if ( GetFamily() == IPv4 )
		{
		char buf[256];
		uint32_t* p = (uint32_t*)&in6.s6_addr[12];
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
		std::string ptr_name("ip6.arpa");
		uint32_t* p = (uint32_t*)in6.s6_addr;

		for ( unsigned int i = 0; i < 4; ++i )
			{
			uint32_t a = ntohl(p[i]);
			for ( unsigned int j = 1; j <= 8; ++j )
				{
				ptr_name.insert(0, 1, '.');
				ptr_name.insert(0, 1, hex_digit[(a >> (32 - j * 4)) & 0x0f]);
				}
			}

		return ptr_name;
		}
	}

IPPrefix::IPPrefix(const in4_addr& in4, uint8_t length) : prefix(in4), length(96 + length)
	{
	if ( length > 32 )
		{
		reporter->Error("Bad in4_addr IPPrefix length : %d", length);
		this->length = 0;
		}

	prefix.Mask(this->length);
	}

IPPrefix::IPPrefix(const in6_addr& in6, uint8_t length) : prefix(in6), length(length)
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

IPPrefix::IPPrefix(const IPAddr& addr, uint8_t length, bool len_is_v6_relative) : prefix(addr)
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

std::string IPPrefix::AsString() const
	{
	char l[16];

	if ( prefix.GetFamily() == IPv4 )
		modp_uitoa10(length - 96, l);
	else
		modp_uitoa10(length, l);

	return prefix.AsString() + "/" + l;
	}

std::unique_ptr<detail::HashKey> IPPrefix::MakeHashKey() const
	{
	struct
		{
		in6_addr ip;
		uint32_t len;
		} key;

	key.ip = prefix.in6;
	key.len = Length();

	return std::make_unique<detail::HashKey>(&key, sizeof(key));
	}

bool IPPrefix::ConvertString(const char* text, IPPrefix* result)
	{
	std::string s(text);
	size_t slash_loc = s.find('/');

	if ( slash_loc == std::string::npos )
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

	} // namespace zeek
