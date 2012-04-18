// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>

#include "config.h"

#include "Net.h"
#include "Var.h"
#include "Discard.h"

Discarder::Discarder()
	{
	check_ip = internal_func("discarder_check_ip");
	check_tcp = internal_func("discarder_check_tcp");
	check_udp = internal_func("discarder_check_udp");
	check_icmp = internal_func("discarder_check_icmp");

	discarder_maxlen = static_cast<int>(opt_internal_int("discarder_maxlen"));
	}

Discarder::~Discarder()
	{
	}

int Discarder::IsActive()
	{
	return check_ip || check_tcp || check_udp || check_icmp;
	}

int Discarder::NextPacket(const IP_Hdr* ip, int len, int caplen)
	{
	int discard_packet = 0;

	if ( check_ip )
		{
		val_list* args = new val_list;
		args->append(ip->BuildPktHdrVal());

		try
			{
			discard_packet = check_ip->Call(args)->AsBool();
			}

		catch ( InterpreterException& e )
			{
			discard_packet = false;
			}

		delete args;

		if ( discard_packet )
			return discard_packet;
		}

	int proto = ip->NextProto();
	if ( proto != IPPROTO_TCP && proto != IPPROTO_UDP &&
	     proto != IPPROTO_ICMP )
		// This is not a protocol we understand.
		return 0;

	// XXX shall we only check the first packet???
	if ( ip->IsFragment() )
		// Never check any fragment.
		return 0;

	int ip_hdr_len = ip->HdrLen();
	len -= ip_hdr_len;	// remove IP header
	caplen -= ip_hdr_len;

	int is_tcp = (proto == IPPROTO_TCP);
	int is_udp = (proto == IPPROTO_UDP);
	int min_hdr_len = is_tcp ?
		sizeof(struct tcphdr) :
		(is_udp ? sizeof(struct udphdr) : sizeof(struct icmp));

	if ( len < min_hdr_len || caplen < min_hdr_len )
		// we don't have a complete protocol header
		return 0;

	// Where the data starts - if this is a protocol we know about,
	// this gets advanced past the transport header.
	const u_char* data = ip->Payload();

	if ( is_tcp )
		{
		if ( check_tcp )
			{
			const struct tcphdr* tp = (const struct tcphdr*) data;
			int th_len = tp->th_off * 4;

			val_list* args = new val_list;
			args->append(ip->BuildPktHdrVal());
			args->append(BuildData(data, th_len, len, caplen));

			try
				{
				discard_packet = check_tcp->Call(args)->AsBool();
				}

			catch ( InterpreterException& e )
				{
				discard_packet = false;
				}

			delete args;
			}
		}

	else if ( is_udp )
		{
		if ( check_udp )
			{
			const struct udphdr* up = (const struct udphdr*) data;
			int uh_len = sizeof (struct udphdr);

			val_list* args = new val_list;
			args->append(ip->BuildPktHdrVal());
			args->append(BuildData(data, uh_len, len, caplen));

			try
				{
				discard_packet = check_udp->Call(args)->AsBool();
				}

			catch ( InterpreterException& e )
				{
				discard_packet = false;
				}

			delete args;
			}
		}

	else
		{
		if ( check_icmp )
			{
			const struct icmp* ih = (const struct icmp*) data;

			val_list* args = new val_list;
			args->append(ip->BuildPktHdrVal());

			try
				{
				discard_packet = check_icmp->Call(args)->AsBool();
				}

			catch ( InterpreterException& e )
				{
				discard_packet = false;
				}

			delete args;
			}
		}

	return discard_packet;
	}

Val* Discarder::BuildData(const u_char* data, int hdrlen, int len, int caplen)
	{
	len -= hdrlen;
	caplen -= hdrlen;
	data += hdrlen;

	len = max(min(min(len, caplen), discarder_maxlen), 0);

	return new StringVal(new BroString(data, len, 1));
	}
