// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/threading/Formatter.h"

#include "zeek/zeek-config.h"

#include <cerrno>

#include "zeek/3rdparty/zeek_inet_ntop.h"
#include "zeek/threading/MsgThread.h"

using zeek::threading::Field;
using zeek::threading::Value;

namespace zeek::threading
	{

Formatter::Formatter(threading::MsgThread* t)
	{
	thread = t;
	}

Formatter::~Formatter() { }

std::string Formatter::Render(const threading::Value::addr_t& addr)
	{
	if ( addr.family == IPv4 )
		{
		char s[INET_ADDRSTRLEN];

		if ( ! zeek_inet_ntop(AF_INET, &addr.in.in4, s, INET_ADDRSTRLEN) )
			return "<bad IPv4 address conversion>";
		else
			return s;
		}
	else
		{
		char s[INET6_ADDRSTRLEN];

		if ( ! zeek_inet_ntop(AF_INET6, &addr.in.in6, s, INET6_ADDRSTRLEN) )
			return "<bad IPv6 address conversion>";
		else
			return s;
		}
	}

TransportProto Formatter::ParseProto(const std::string& proto) const
	{
	if ( proto == "unknown" )
		return TRANSPORT_UNKNOWN;
	else if ( proto == "tcp" )
		return TRANSPORT_TCP;
	else if ( proto == "udp" )
		return TRANSPORT_UDP;
	else if ( proto == "icmp" )
		return TRANSPORT_ICMP;

	thread->Warning(thread->Fmt("Tried to parse invalid/unknown protocol: %s", proto.c_str()));

	return TRANSPORT_UNKNOWN;
	}

// More or less verbose copy from IPAddr.cc -- which uses reporter.
threading::Value::addr_t Formatter::ParseAddr(const std::string& s) const
	{
	threading::Value::addr_t val;

	if ( s.find(':') == std::string::npos ) // IPv4.
		{
		val.family = IPv4;

		if ( inet_aton(s.c_str(), &(val.in.in4)) <= 0 )
			{
			thread->Warning(thread->Fmt("Bad address: %s", s.c_str()));
			memset(&val.in.in4.s_addr, 0, sizeof(val.in.in4.s_addr));
			}
		}

	else
		{
		val.family = IPv6;
		std::string clean_s = s;
		if ( s.front() == '[' && s.back() == ']' )
			clean_s = s.substr(1, s.length() - 2);
		if ( inet_pton(AF_INET6, clean_s.c_str(), val.in.in6.s6_addr) <= 0 )
			{
			thread->Warning(thread->Fmt("Bad address: %s", clean_s.c_str()));
			memset(val.in.in6.s6_addr, 0, sizeof(val.in.in6.s6_addr));
			}
		}

	return val;
	}

std::string Formatter::Render(const threading::Value::subnet_t& subnet)
	{
	char l[16];

	if ( subnet.prefix.family == IPv4 )
		modp_uitoa10(subnet.length - 96, l);
	else
		modp_uitoa10(subnet.length, l);

	std::string s = Render(subnet.prefix) + "/" + l;

	return s;
	}

std::string Formatter::Render(double d)
	{
	char buf[256];
	modp_dtoa(d, buf, 6);
	return buf;
	}

std::string Formatter::Render(TransportProto proto)
	{
	if ( proto == TRANSPORT_UDP )
		return "udp";
	else if ( proto == TRANSPORT_TCP )
		return "tcp";
	else if ( proto == TRANSPORT_ICMP )
		return "icmp";
	else
		return "unknown";
	}

	} // namespace zeek::threading::formatter
