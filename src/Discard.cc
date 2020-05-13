// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "Discard.h"

#include <algorithm>

#include "BroString.h"
#include "Net.h"
#include "Func.h"
#include "Var.h"
#include "Val.h"
#include "IP.h"
#include "Reporter.h" // for InterpreterException

Discarder::Discarder()
	{
	check_ip = zeek::id::lookup_func("discarder_check_ip");
	check_tcp = zeek::id::lookup_func("discarder_check_tcp");
	check_udp = zeek::id::lookup_func("discarder_check_udp");
	check_icmp = zeek::id::lookup_func("discarder_check_icmp");

	discarder_maxlen = static_cast<int>(opt_internal_int("discarder_maxlen"));
	}

Discarder::~Discarder()
	{
	}

bool Discarder::IsActive()
	{
	return check_ip || check_tcp || check_udp || check_icmp;
	}

bool Discarder::NextPacket(const IP_Hdr* ip, int len, int caplen)
	{
	bool discard_packet = false;

	if ( check_ip )
		{
		zeek::Args args{ip->ToPktHdrVal()};

		try
			{
			discard_packet = check_ip->Call(args)->AsBool();
			}

		catch ( InterpreterException& e )
			{
			discard_packet = false;
			}

		if ( discard_packet )
			return discard_packet;
		}

	int proto = ip->NextProto();
	if ( proto != IPPROTO_TCP && proto != IPPROTO_UDP &&
	     proto != IPPROTO_ICMP )
		// This is not a protocol we understand.
		return false;

	// XXX shall we only check the first packet???
	if ( ip->IsFragment() )
		// Never check any fragment.
		return false;

	int ip_hdr_len = ip->HdrLen();
	len -= ip_hdr_len;	// remove IP header
	caplen -= ip_hdr_len;

	bool is_tcp = (proto == IPPROTO_TCP);
	bool is_udp = (proto == IPPROTO_UDP);
	int min_hdr_len = is_tcp ?
		sizeof(struct tcphdr) :
		(is_udp ? sizeof(struct udphdr) : sizeof(struct icmp));

	if ( len < min_hdr_len || caplen < min_hdr_len )
		// we don't have a complete protocol header
		return false;

	// Where the data starts - if this is a protocol we know about,
	// this gets advanced past the transport header.
	const u_char* data = ip->Payload();

	if ( is_tcp )
		{
		if ( check_tcp )
			{
			const struct tcphdr* tp = (const struct tcphdr*) data;
			int th_len = tp->th_off * 4;

			zeek::Args args{
				ip->ToPktHdrVal(),
				{AdoptRef{}, BuildData(data, th_len, len, caplen)},
			};

			try
				{
				discard_packet = check_tcp->Call(args)->AsBool();
				}

			catch ( InterpreterException& e )
				{
				discard_packet = false;
				}
			}
		}

	else if ( is_udp )
		{
		if ( check_udp )
			{
			const struct udphdr* up = (const struct udphdr*) data;
			int uh_len = sizeof (struct udphdr);

			zeek::Args args{
				ip->ToPktHdrVal(),
				{AdoptRef{}, BuildData(data, uh_len, len, caplen)},
			};

			try
				{
				discard_packet = check_udp->Call(args)->AsBool();
				}

			catch ( InterpreterException& e )
				{
				discard_packet = false;
				}
			}
		}

	else
		{
		if ( check_icmp )
			{
			const struct icmp* ih = (const struct icmp*) data;

			zeek::Args args{ip->ToPktHdrVal()};

			try
				{
				discard_packet = check_icmp->Call(args)->AsBool();
				}

			catch ( InterpreterException& e )
				{
				discard_packet = false;
				}
			}
		}

	return discard_packet;
	}

Val* Discarder::BuildData(const u_char* data, int hdrlen, int len, int caplen)
	{
	len -= hdrlen;
	caplen -= hdrlen;
	data += hdrlen;

	len = std::max(std::min(std::min(len, caplen), discarder_maxlen), 0);

	return new StringVal(new BroString(data, len, true));
	}
