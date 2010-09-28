// $Id: Discard.cc 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "Net.h"
#include "Var.h"
#include "Discard.h"

Discarder::Discarder()
	{
	ip_hdr = internal_type("ip_hdr")->AsRecordType();
	tcp_hdr = internal_type("tcp_hdr")->AsRecordType();
	udp_hdr = internal_type("udp_hdr")->AsRecordType();
	icmp_hdr = internal_type("icmp_hdr")->AsRecordType();

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

	const struct ip* ip4 = ip->IP4_Hdr();

	if ( check_ip )
		{
		val_list* args = new val_list;
		args->append(BuildHeader(ip4));
		discard_packet = check_ip->Call(args)->AsBool();
		delete args;

		if ( discard_packet )
			return discard_packet;
		}

	int proto = ip4->ip_p;
	if ( proto != IPPROTO_TCP && proto != IPPROTO_UDP &&
	     proto != IPPROTO_ICMP )
		// This is not a protocol we understand.
		return 0;

	// XXX shall we only check the first packet???
	uint32 frag_field = ntohs(ip4->ip_off);
	if ( (frag_field & 0x3fff) != 0 )
		// Never check any fragment.
		return 0;

	int ip_hdr_len = ip4->ip_hl * 4;
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
	const u_char* data = ((u_char*) ip4 + ip_hdr_len);

	if ( is_tcp )
		{
		if ( check_tcp )
			{
			const struct tcphdr* tp = (const struct tcphdr*) data;
			int th_len = tp->th_off * 4;

			val_list* args = new val_list;
			args->append(BuildHeader(ip4));
			args->append(BuildHeader(tp, len));
			args->append(BuildData(data, th_len, len, caplen));
			discard_packet = check_tcp->Call(args)->AsBool();
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
			args->append(BuildHeader(ip4));
			args->append(BuildHeader(up));
			args->append(BuildData(data, uh_len, len, caplen));
			discard_packet = check_udp->Call(args)->AsBool();
			delete args;
			}
		}

	else
		{
		if ( check_icmp )
			{
			const struct icmp* ih = (const struct icmp*) data;

			val_list* args = new val_list;
			args->append(BuildHeader(ip4));
			args->append(BuildHeader(ih));
			discard_packet = check_icmp->Call(args)->AsBool();
			delete args;
			}
		}

	return discard_packet;
	}

Val* Discarder::BuildHeader(const struct ip* ip)
	{
	RecordVal* hdr = new RecordVal(ip_hdr);

	hdr->Assign(0, new Val(ip->ip_hl * 4, TYPE_COUNT));
	hdr->Assign(1, new Val(ip->ip_tos, TYPE_COUNT));
	hdr->Assign(2, new Val(ntohs(ip->ip_len), TYPE_COUNT));
	hdr->Assign(3, new Val(ntohs(ip->ip_id), TYPE_COUNT));
	hdr->Assign(4, new Val(ip->ip_ttl, TYPE_COUNT));
	hdr->Assign(5, new Val(ip->ip_p, TYPE_COUNT));
	hdr->Assign(6, new AddrVal(ip->ip_src.s_addr));
	hdr->Assign(7, new AddrVal(ip->ip_dst.s_addr));

	return hdr;
	}

Val* Discarder::BuildHeader(const struct tcphdr* tp, int tcp_len)
	{
	RecordVal* hdr = new RecordVal(tcp_hdr);

	hdr->Assign(0, new PortVal(ntohs(tp->th_sport), TRANSPORT_TCP));
	hdr->Assign(1, new PortVal(ntohs(tp->th_dport), TRANSPORT_TCP));
	hdr->Assign(2, new Val(uint32(ntohl(tp->th_seq)), TYPE_COUNT));
	hdr->Assign(3, new Val(uint32(ntohl(tp->th_ack)), TYPE_COUNT));

	int tcp_hdr_len = tp->th_off * 4;

	hdr->Assign(4, new Val(tcp_hdr_len, TYPE_COUNT));
	hdr->Assign(5, new Val(tcp_len - tcp_hdr_len, TYPE_COUNT));

	hdr->Assign(6, new Val(tp->th_flags, TYPE_COUNT));
	hdr->Assign(7, new Val(ntohs(tp->th_win), TYPE_COUNT));

	return hdr;
	}

Val* Discarder::BuildHeader(const struct udphdr* up)
	{
	RecordVal* hdr = new RecordVal(udp_hdr);

	hdr->Assign(0, new PortVal(ntohs(up->uh_sport), TRANSPORT_UDP));
	hdr->Assign(1, new PortVal(ntohs(up->uh_dport), TRANSPORT_UDP));
	hdr->Assign(2, new Val(ntohs(up->uh_ulen), TYPE_COUNT));

	return hdr;
	}

Val* Discarder::BuildHeader(const struct icmp* icmp)
	{
	RecordVal* hdr = new RecordVal(icmp_hdr);

	hdr->Assign(0, new Val(icmp->icmp_type, TYPE_COUNT));

	return hdr;
	}

Val* Discarder::BuildData(const u_char* data, int hdrlen, int len, int caplen)
	{
	len -= hdrlen;
	caplen -= hdrlen;
	data += hdrlen;

	len = max(min(min(len, caplen), discarder_maxlen), 0);

	return new StringVal(new BroString(data, len, 1));
	}
