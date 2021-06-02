// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/tcp/TCP.h"
#include "zeek/RunState.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/packet_analysis/protocol/tcp/TCPSessionAdapter.h"

#include "zeek/analyzer/protocol/tcp/events.bif.h"
#include "zeek/analyzer/protocol/tcp/types.bif.h"

using namespace zeek;
using namespace zeek::packet_analysis::TCP;
using namespace zeek::packet_analysis::IP;

TCPAnalyzer::TCPAnalyzer() : IPBasedAnalyzer("TCP", TRANSPORT_TCP, TCP_PORT_MASK, false)
	{
	}

void TCPAnalyzer::Initialize()
	{
	ignored_nets = zeek::id::find_val<TableVal>("ignore_checksums_nets");
	}

SessionAdapter* TCPAnalyzer::MakeSessionAdapter(Connection* conn)
	{
	auto* root = new TCPSessionAdapter(conn);
	root->SetParent(this);

	conn->EnableStatusUpdateTimer();
	conn->SetInactivityTimeout(zeek::detail::udp_inactivity_timeout);

	return root;
	}

zeek::analyzer::pia::PIA* TCPAnalyzer::MakePIA(Connection* conn)
	{
	return new analyzer::pia::PIA_TCP(conn);
	}

bool TCPAnalyzer::BuildConnTuple(size_t len, const uint8_t* data, Packet* packet,
                                 ConnTuple& tuple)
	{
	uint32_t min_hdr_len = sizeof(struct tcphdr);
	if ( ! CheckHeaderTrunc(min_hdr_len, len, packet) )
		return false;

	tuple.src_addr = packet->ip_hdr->SrcAddr();
	tuple.dst_addr = packet->ip_hdr->DstAddr();

	data = packet->ip_hdr->Payload();

	const struct tcphdr* tp = (const struct tcphdr *) data;
	tuple.src_port = tp->th_sport;
	tuple.dst_port = tp->th_dport;
	tuple.is_one_way = false;
	tuple.proto = TRANSPORT_TCP;

	return true;
	}

bool TCPAnalyzer::WantConnection(uint16_t src_port, uint16_t dst_port,
                                 const u_char* data, bool& flip_roles) const
	{
	flip_roles = false;
	const struct tcphdr* tp = (const struct tcphdr*) data;
	uint8_t tcp_flags = tp->th_flags;

	if ( ! (tcp_flags & TH_SYN) || (tcp_flags & TH_ACK) )
		{
		// The new connection is starting either without a SYN,
		// or with a SYN ack. This means it's a partial connection.
		if ( ! zeek::detail::partial_connection_ok )
			return false;

		if ( tcp_flags & TH_SYN && ! zeek::detail::tcp_SYN_ack_ok )
			return false;

		// Try to guess true responder by the port numbers.
		// (We might also think that for SYN acks we could
		// safely flip the roles, but that doesn't work
		// for stealth scans.)
		if ( IsLikelyServerPort(src_port) )
			{ // connection is a candidate for flipping
			if ( IsLikelyServerPort(dst_port) )
				// Hmmm, both source and destination
				// are plausible.  Heuristic: flip only
				// if (1) this isn't a SYN ACK (to avoid
				// confusing stealth scans) and
				// (2) dest port > src port (to favor
				// more plausible servers).
				flip_roles = ! (tcp_flags & TH_SYN) && src_port < dst_port;
			else
				// Source is plausible, destination isn't.
				flip_roles = true;
			}
		}

	return true;
	}

void TCPAnalyzer::DeliverPacket(Connection* c, double t, bool is_orig, int remaining, Packet* pkt)
	{
	const u_char* data = pkt->ip_hdr->Payload();
	int len = pkt->ip_hdr->PayloadLen();
	auto* adapter = static_cast<TCPSessionAdapter*>(c->GetSessionAdapter());

	const struct tcphdr* tp = ExtractTCP_Header(data, len, remaining, adapter);
	if ( ! tp )
		return;

	// We need the min() here because Ethernet frame padding can lead to
	// remaining > len.
	if ( packet_contents )
		adapter->PacketContents(data, std::min(len, remaining));

	analyzer::tcp::TCP_Endpoint* endpoint = is_orig ? adapter->orig : adapter->resp;
	analyzer::tcp::TCP_Endpoint* peer = endpoint->peer;
	const std::unique_ptr<IP_Hdr>& ip = pkt->ip_hdr;

	if ( ! ValidateChecksum(ip.get(), tp, endpoint, len, remaining, adapter) )
		return;

	adapter->Process(is_orig, tp, len, ip, data, remaining);

	// Send the packet back into the packet analysis framework.
	ForwardPacket(len, data, pkt);

	// Call DeliverPacket on the adapter directly here. Normally we'd call ForwardPacket
	// but this adapter does some other things in its DeliverPacket with the packet children
	// analyzers.
	adapter->DeliverPacket(len, data, is_orig, adapter->LastRelDataSeq(), ip.get(), remaining);
	}

const struct tcphdr* TCPAnalyzer::ExtractTCP_Header(const u_char*& data, int& len, int& remaining,
                                                    TCPSessionAdapter* adapter)
	{
	const struct tcphdr* tp = (const struct tcphdr*) data;
	uint32_t tcp_hdr_len = tp->th_off * 4;

	if ( tcp_hdr_len < sizeof(struct tcphdr) )
		{
		adapter->Weird("bad_TCP_header_len");
		return nullptr;
		}

	if ( tcp_hdr_len > uint32_t(len) ||
	     tcp_hdr_len > uint32_t(remaining) )
		{
		// This can happen even with the above test, due to TCP options.
		adapter->Weird("truncated_header");
		return nullptr;
		}

	len -= tcp_hdr_len;	// remove TCP header
	remaining -= tcp_hdr_len;
	data += tcp_hdr_len;

	return tp;
	}

bool TCPAnalyzer::ValidateChecksum(const IP_Hdr* ip, const struct tcphdr* tp,
                                   analyzer::tcp::TCP_Endpoint* endpoint, int len, int caplen,
                                   TCPSessionAdapter* adapter)
	{
	if ( ! run_state::current_pkt->l3_checksummed &&
	     ! detail::ignore_checksums &&
	     ! ignored_nets->Contains(ip->IPHeaderSrcAddr()) &&
	     caplen >= len && ! endpoint->ValidChecksum(tp, len, ip->IP4_Hdr()) )
		{
		adapter->Weird("bad_TCP_checksum");
		endpoint->ChecksumError();
		return false;
		}
	else
		return true;
	}
