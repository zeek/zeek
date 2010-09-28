// $Id:$
//
// See the file "COPYING" in the main distribution directory for copyright.


#include "config.h"

#include <assert.h>
#include <stdlib.h>

#include "Event.h"
#include "Net.h"
#include "UDP_Rewriter.h"

#define MSG_PREFIX	"UDP trace rewriter: "
#define DEBUG_MSG_A(x...)
// #define DEBUG_MSG_A	DEBUG_MSG


UDP_Rewriter::UDP_Rewriter(Analyzer* arg_analyzer, int arg_MTU,
				PacketDumper* arg_dumper)
	{
	analyzer = arg_analyzer;
	MTU = arg_MTU;
	dumper = arg_dumper;
	packets_rewritten = 0;
	current_packet = next_packet = 0;

	if ( anonymize_ip_addr )
		{
		anon_addr[0] = anonymize_ip(to_v4_addr(analyzer->Conn()->OrigAddr()),
						ORIG_ADDR);
		anon_addr[1] = anonymize_ip(to_v4_addr(analyzer->Conn()->RespAddr()),
						RESP_ADDR);
		}
	else
		anon_addr[0] = anon_addr[1] = 0;
	}

void UDP_Rewriter::Done()
	{
	}

UDP_Rewriter::~UDP_Rewriter()
	{
	delete current_packet;
	}

void UDP_Rewriter::WriteData(int is_orig, int len, const u_char* data)
	{
	DoWriteData(is_orig, len, data);
	}

void UDP_Rewriter::DoWriteData(int is_orig, int len, const u_char* data)
	{
 	struct pcap_pkthdr* hdr;
	int length = len;
	ipaddr32_t src = 0, dst = 0;

	current_packet->AppendData(data,len);
	// Mark data to be written.
	current_packet->SetModified();
	}

// Compose the packet so it can be written.
// Compute UDP/IP checksums, lengths, addresses.
int UDP_TracePacket::BuildPacket(struct pcap_pkthdr*& hdr,
				const u_char*& arg_pkt, int& length,
				ipaddr32_t anon_src, ipaddr32_t anon_dst)
	{
	struct ip* ip = (struct ip*) (pkt + ip_offset);
	struct udphdr* up = (struct udphdr*) (pkt + udp_offset);
	uint32 sum = 0;

	// Fix IP addresses before computing the UDP checksum
	if ( anonymize_ip_addr )
		{
		ip->ip_src.s_addr = anon_src;
		ip->ip_dst.s_addr = anon_dst;
		}

	// Create the IP header.
	ip->ip_off = 0;
	ip->ip_sum = 0;
	ip->ip_hl = (udp_offset - ip_offset) >> 2;
	ip->ip_len = htons(buffer_offset - ip_offset);
	ip->ip_off = 0;	// DF = 0, MF = 0, offset = 0
	ip->ip_sum = 0;
	ip->ip_sum = 0xffff - ones_complement_checksum((const void*) ip,
						(udp_offset-ip_offset), sum);

	pcap_hdr.caplen = pcap_hdr.len = buffer_offset;

	hdr = &pcap_hdr;
	arg_pkt = pkt;
	length = buffer_offset;

	// Create the UDP header.
	up->uh_ulen = htons(buffer_offset - udp_offset);
	up->uh_sum = 0;
	up->uh_sum = 0xffff - udp_checksum(ip, up, buffer_offset - udp_offset);

	// Create the pcap header.
	//
	// The below works around a potential type incompatibility
	// on systems where pcap's timeval is different from the
	// system-wide one. --cpk
	//
	timeval tv_tmp = double_to_timeval(timestamp);
	pcap_hdr.ts.tv_sec = tv_tmp.tv_sec;
	pcap_hdr.ts.tv_usec = tv_tmp.tv_usec;
	pcap_hdr.caplen = pcap_hdr.len = buffer_offset;

	hdr = &pcap_hdr;
	arg_pkt = pkt;
	length = buffer_offset;

	return 1;
	}

void UDP_Rewriter::NextPacket(int is_orig, double t,
				const struct pcap_pkthdr* pcap_hdr,
				const u_char* pcap_pkt, int hdr_size,
				const struct ip* ip, const struct udphdr* up)
	{
	unsigned int ip_hdr_len = ip->ip_hl * 4;

	// Cache the packet ....
	UDP_TracePacket* p = new UDP_TracePacket(this, t, is_orig,
				pcap_hdr, /*MTU */ 1024,
				hdr_size + ip_hdr_len + sizeof(struct udphdr));

	if ( ! p->AppendLinkHeader(pcap_pkt, hdr_size) )
		internal_error(MSG_PREFIX "cannot append headers -- check MTU");

	if ( ! p->AppendIPHeader((const u_char*) ip, sizeof(*ip)) )
		internal_error(MSG_PREFIX "cannot append headers -- check MTU");

	if ( ! p->AppendUDPHeader((const u_char*) up, sizeof(*up)) )
		internal_error(MSG_PREFIX "cannot append headers -- check MTU");

	// We only ever use one packet in UDP.
	// ### This is potentially a leak.
	next_packet = current_packet = p;
	}

void UDP_Rewriter::Push(int)
	{
	internal_error("UDP_Rewriter::Push not implemented");
	}

void UDP_Rewriter::AbortPackets(int)
	{
	internal_error("UDP_Rewriter::AbortPackets not implemented");
	}

unsigned int UDP_Rewriter::ReserveSlot()
	{
	internal_error("UDP_Rewriter::ReserveSlot not implemented");
	return 0;
	}

int UDP_Rewriter::SeekSlot(unsigned int)
	{
	internal_error("UDP_Rewriter::SeekSlot not implemented");
	return 0;
	}

int UDP_Rewriter::ReturnFromSlot()
	{
	internal_error("UDP_Rewriter::ReturnFromSlot not implemented");
	return 0;
	}
int UDP_Rewriter::ReleaseSlot(unsigned int)
	{
	internal_error("UDP_Rewriter::ReleaseSlot not implemented");
	return 0;
	}

int UDP_Rewriter::LeaveAddrInTheClear(int is_orig)
	{
	internal_error("UDP_Rewriter::LeaveAddrInTheClear not implemented");
	return 0;
	}

void UDP_Rewriter::CommitPackets(int commit)
	{
	if ( current_packet && current_packet->IsModified() )
		{
		ipaddr32_t anon_src = 0, anon_dst = 0;

		if ( current_packet->IsOrig() )
			{
			anon_src = anon_addr[0];
			anon_dst = anon_addr[1];
			}
		else
			{
			anon_src = anon_addr[1];
			anon_dst = anon_addr[0];
			}

		struct pcap_pkthdr* hdr;
		const u_char* pkt;
		int len;
		current_packet->BuildPacket(hdr, pkt, len, anon_src, anon_dst);

		dumper->DumpPacket(hdr, pkt, hdr->caplen);
		}

	delete current_packet;
	next_packet = current_packet = 0;

	++packets_rewritten;
	}

UDP_TracePacket::UDP_TracePacket(UDP_Rewriter* arg_trace_rewriter,
					double t, int arg_is_orig,
					const struct pcap_pkthdr* arg_hdr,
					int MTU, int initial_size)
	{
	trace_rewriter = arg_trace_rewriter;
	pcap_hdr = *arg_hdr;
	// packet_seq = arg_packet_seq;
	timestamp = t;
	is_orig = arg_is_orig;
	mtu = MTU;
	buffer_size = initial_size;
	buffer_offset = 0;

	pkt = new u_char[buffer_size];

	ip_offset = udp_offset = data_offset = -1;

	reuse = 0;
	on_hold = 0;
	modified = 0;
	seq_gap = 0;

	packet_val = 0;
	packet_val = PacketVal();
	}

UDP_TracePacket::~UDP_TracePacket()
	{
	packet_val->SetOrigin(0);
	Unref(packet_val);
	delete [] pkt;
	}

RecordVal* UDP_TracePacket::PacketVal()
	{
	if ( packet_val )
		Ref(packet_val);
	else
		{
		packet_val = new RecordVal(packet_type);
		packet_val->Assign(0, TraceRewriter()->GetAnalyzer()->BuildConnVal());
		packet_val->Assign(1, new Val(IsOrig(), TYPE_BOOL));
		packet_val->Assign(2, new Val(TimeStamp(), TYPE_TIME));
		packet_val->SetOrigin(this);
		}

	return packet_val;
	}

int UDP_TracePacket::AppendLinkHeader(const u_char* chunk, int len)
	{
	if ( ip_offset >= 0 && ip_offset != buffer_offset )
		internal_error(MSG_PREFIX "link header must be appended before IP header");

	if ( ! Append(chunk, len) )
		return 0;

	ip_offset = buffer_offset;
	return 1;
	}

int UDP_TracePacket::AppendIPHeader(const u_char* chunk, int len)
	{
	if ( udp_offset >= 0 && udp_offset != buffer_offset )
		internal_error(MSG_PREFIX "IP header must be appended before udp header");

	if ( ! Append(chunk, len) )
		return 0;

	udp_offset = buffer_offset;
	return 1;
	}

int UDP_TracePacket::AppendUDPHeader(const u_char* chunk, int len)
	{
	if ( data_offset >= 0 && data_offset != buffer_offset )
		internal_error(MSG_PREFIX "tcp header must be appended before payload");

	if ( udp_offset == buffer_offset )
		{ // first UDP header chunk
		int extra = (udp_offset - ip_offset) % 4;
		if ( extra )
			{
			DEBUG_MSG(MSG_PREFIX "padding IP header");
			if ( ! AppendIPHeader(0, 4 - extra) )
				return 0;
			}
		}

	if ( ! Append(chunk, len) )
		return 0;

	data_offset = buffer_offset;
	return 1;
	}

int UDP_TracePacket::AppendData(const u_char* chunk, int len)
	{
	// All headers must be appended before any data.
	ASSERT(ip_offset >= 0 && udp_offset >= 0 && data_offset >= 0);

	if ( data_offset == buffer_offset )
		{ // first data chunk
		int extra = (data_offset - udp_offset) % 4;
		if ( extra )
			{
			if ( ! AppendUDPHeader(0, 4 - extra) )
				return 0;
			}
		}

	if ( ! Append(chunk, len) )
		return 0;

	return 1;
	}

int UDP_TracePacket::Append(const u_char* chunk, int len)
	{
	if ( buffer_offset + len > buffer_size )
		{
		if ( buffer_offset + len > mtu )
			return 0;

		u_char* tmp = new u_char[mtu];
		for ( int i = 0 ; i < buffer_size; ++i )
			tmp[i] = pkt[i];

		delete [] pkt;
		pkt = tmp;
		buffer_size = mtu;
		}

	ASSERT(buffer_offset + len <= buffer_size);

	if ( chunk )
		memcpy(pkt + buffer_offset, chunk, len);
	else
		// Fill with 0.
		memset(pkt + buffer_offset, 0, len);

	buffer_offset += len;

	return 1;
	}
