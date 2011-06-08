// $Id: ConnCompressor.cc 7008 2010-03-25 02:42:20Z vern $

#include <arpa/inet.h>

#include "ConnCompressor.h"
#include "Event.h"
#include "ConnSizeAnalyzer.h"
#include "net_util.h"

// The basic model of the compressor is to wait for an answer before
// instantiating full connection state.  Until we see a reply, only a minimal
// amount of state is stored.  This has some consequences:
//
// - We try to mimic TCP.cc as close as possible, but this works only to a
//   certain degree; e.g., we don't consider any of the wait-a-bit-after-
//   the-connection-has-been-closed timers. That means we will get differences
//   in connection semantics if the compressor is turned on. On the other
//   hand, these differences will occur only for not well-established
//   sessions, and experience shows that for these kinds of connections
//   semantics are ill-defined in any case.
//
// - If an originator sends multiple different packets before we see a reply,
//   we lose the information about additional packets (more precisely, we
//   merge the packet headers into one). In particular, we lose any payload.
//   This is a major problem if we see only one direction of a connection.
//   When analyzing only SYN/FIN/RSTs this leads to differences if we miss
//   the SYN/ACK.
//
//   To avoid losing payload, there is the option cc_instantiate_on_data:
//   if enabled and the originator sends a non-control packet after the
//   initial packet, we instantiate full connection state.
//
// - We lose some of the information contained in initial packets (e.g., most
//   IP/TCP options and any payload). If you depend on them, you don't
//   want to use the compressor.
//
//   Optionally, the compressor can take care only of initial SYNs and
//   instantiate full connection state for all other connection setups.
//   To enable, set cc_handle_only_syns to true.
//
// - The compressor may handle refused connections (i.e., initial packets
//   followed by RST from responder) itself. Again, this leads to differences
//   from default TCP processing and is therefore turned off by default.
//   To enable, set cc_handle_resets to true.
//
// - We don't match signatures on connections which are completely handled
//   by the compressor. Matching would require significant additional state
//   w/o being very helpful.
//
// - If use_conn_size_analyzer is True, the reported counts for bytes and
//   packets may not account for some packets/data that is part of those
//   packets which the connection compressor handles. The error, if any, will
//   however be small.


#ifdef DEBUG
static inline const char* fmt_conn_id(const ConnCompressor::PendingConn* c)
	{
	if ( c->ip1_is_src )
		return fmt_conn_id(c->key.ip1, c->key.port1,
					c->key.ip2, c->key.port2);
	else
		return fmt_conn_id(c->key.ip2, c->key.port2,
					c->key.ip1, c->key.port1);
	}

static inline const char* fmt_conn_id(const Connection* c)
	{
	return fmt_conn_id(c->OrigAddr(), c->OrigPort(),
				c->RespAddr(), c->RespPort());
	}

static inline const char* fmt_conn_id(const IP_Hdr* ip)
	{
	const struct tcphdr* tp = (const struct tcphdr*) ip->Payload();
	return fmt_conn_id(ip->SrcAddr(), tp->th_sport,
				ip->DstAddr(), tp->th_dport);
	}
#endif

ConnCompressor::ConnCompressor()
	{
	first_block = last_block = 0;
	first_non_expired = 0;
	conn_val = 0;

	sizes.connections = sizes.connections_total = 0;
	sizes.pending_valid = sizes.pending_total = sizes.pending_in_mem = 0;
	sizes.hash_table_size = 0;
	sizes.memory = 0;
	}

ConnCompressor::~ConnCompressor()
	{
	Block* next;
	for ( Block* b = first_block; b; b = next )
		{
		next = b->next;
		delete b;
		}
	}

Connection* ConnCompressor::NextPacket(double t, HashKey* key, const IP_Hdr* ip,
		const struct pcap_pkthdr* hdr, const u_char* const pkt)
	{
	// Expire old stuff.
	DoExpire(t);

	// Most sanity checks on header sizes are already done ...
	const struct tcphdr* tp = (const struct tcphdr*) ip->Payload();

	// ... except this one.
	uint32 tcp_hdr_len = tp->th_off * 4;
	if ( tcp_hdr_len > uint32(ip->TotalLen() - ip->HdrLen()) )
		{
		sessions->Weird("truncated_header", hdr, pkt);
		delete key;
		return 0;
		}

	bool external = current_iosrc->GetCurrentTag();
	ConnData* c = conns.Lookup(key);

	Unref(conn_val);
	conn_val = 0;

	// Do we already have a Connection object?
	if ( c && IsConnPtr(c) )
		{
		Connection* conn = MakeConnPtr(c);
		int consistent = 1;

		if ( external )
			{
			// External, and we already have a full connection.
			// That means we use the same logic as in NetSessions
			// to compare the tags.
			consistent = sessions->CheckConnectionTag(conn);
			if ( consistent < 0 )
				{
				delete key;
				return 0;
				}
			}

		if ( ! consistent || conn->IsReuse(t, ip->Payload()) )
			{
			if ( consistent )
				{
				DBG_LOG(DBG_COMPRESSOR, "%s reuse", fmt_conn_id(conn));
				conn->Event(connection_reused, 0);
				}

			sessions->Remove(conn);
			--sizes.connections;

			return Instantiate(t, key, ip);
			}

		DBG_LOG(DBG_COMPRESSOR, "%s pass through", fmt_conn_id(conn));
		delete key;
		return conn;
		}

	PendingConn* pending = c ? MakePendingConnPtr(c) : 0;

	if ( c && external )
		{
		// External, but previous packets were not, i.e., they used
		// the global timer queue.  We finish the old connection
		// and instantiate a full one now.
		DBG_LOG(DBG_TM, "got packet with tag %s for already"
				"known cc connection, instantiating full conn",
				current_iosrc->GetCurrentTag()->c_str());

		Event(pending, 0, connection_attempt,
			TCP_ENDPOINT_INACTIVE, 0, TCP_ENDPOINT_INACTIVE);
		Event(pending, 0, connection_state_remove,
			TCP_ENDPOINT_INACTIVE, 0, TCP_ENDPOINT_INACTIVE);
		Remove(key);

		return Instantiate(t, key, ip);
		}

	if ( c && pending->invalid &&
	     network_time < pending->time + tcp_session_timer )
		{
		// The old connection has terminated sooner than
		// tcp_session_timer.  We assume this packet to be
		// a latecomer, and ignore it.
		DBG_LOG(DBG_COMPRESSOR, "%s ignored", fmt_conn_id(pending));
		sessions->DumpPacket(hdr, pkt);
		delete key;
		return 0;
		}

	// Simulate tcp_{reset,close}_delay for initial FINs/RSTs
	if ( c && ! pending->invalid &&
	     ((pending->FIN && pending->time + tcp_close_delay < t ) ||
	      (pending->RST && pending->time + tcp_reset_delay < t )) )
		{
		DBG_LOG(DBG_COMPRESSOR, "%s closed", fmt_conn_id(pending));
		int orig_state =
			pending->FIN ? TCP_ENDPOINT_CLOSED : TCP_ENDPOINT_RESET;

		Event(pending, 0, connection_partial_close, orig_state,
			ip->PayloadLen() - (tp->th_off * 4),
			TCP_ENDPOINT_INACTIVE);
		Event(pending, 0, connection_state_remove, orig_state,
			ip->PayloadLen() - (tp->th_off * 4),
			TCP_ENDPOINT_INACTIVE);

		Remove(key);

		Connection* tc = FirstFromOrig(t, key, ip, tp);
		if ( ! tc )
			{
			delete key;
			sessions->DumpPacket(hdr, pkt);
			}

		return tc;
		}

	Connection* tc;

	if ( ! c || pending->invalid )
		{
		// First packet of a connection.
		if ( c )
			Remove(key);

		if ( external  )
			// External, we directly instantiate a full connection.
			tc = Instantiate(t, key, ip);
		else
			tc = FirstFromOrig(t, key, ip, tp);
		}

	else if ( addr_eq(ip->SrcAddr(), SrcAddr(pending)) &&
		  tp->th_sport == SrcPort(pending) )
		// Another packet from originator.
		tc = NextFromOrig(pending, t, key, ip, tp);

	else
		// A reply.
		tc = Response(pending, t, key, ip, tp);

	if ( ! tc )
		{
		delete key;
		sessions->DumpPacket(hdr, pkt);
		}

	return tc;
	}

static int parse_tcp_options(unsigned int opt, unsigned int optlen,
				const u_char* option, TCP_Analyzer* analyzer,
				bool is_orig, void* cookie)
	{
	ConnCompressor::PendingConn* c = (ConnCompressor::PendingConn*) cookie;

	// We're only interested in window_scale.
	if ( opt == 3 )
		c->window_scale = option[2];

	return 0;
	}

Connection* ConnCompressor::FirstFromOrig(double t, HashKey* key,
					const IP_Hdr* ip, const tcphdr* tp)
	{
	if ( cc_handle_only_syns && ! (tp->th_flags & TH_SYN) )
		return Instantiate(t, key, ip);

	// The first packet of a connection.
	PendingConn* pending = MakeNewState(t);
	PktHdrToPendingConn(t, key, ip, tp, pending);

	DBG_LOG(DBG_COMPRESSOR, "%s our", fmt_conn_id(pending));

	// The created DictEntry will point directly into our PendingConn.
	// So, we have to be careful when we delete it.
	conns.Dictionary::Insert(&pending->key, sizeof(pending->key),
				pending->hash, MakeMapPtr(pending), 0);

	// Mimic some of TCP_Analyzer's weirds for SYNs.
	// To be completely precise, we'd need to check this at a few
	// more locations in NextFromOrig() and Reply().  However, that
	// does not really seem worth it, as this is the standard case.
	if ( tp->th_flags & TH_SYN )
		{
		if ( tp->th_flags & TH_RST )
			Weird(pending, t, "TCP_christmas");

		if ( tp->th_flags & TH_URG )
			Weird(pending, t, "baroque_SYN");

		int len = ip->TotalLen() - ip->HdrLen() - tp->th_off * 4;

		if ( len > 0 )
			// T/TCP definitely complicates this.
			Weird(pending, t, "SYN_with_data");
		}

	if ( tp->th_flags & TH_FIN )
		{
		if ( ! (tp->th_flags & TH_SYN) )
			Weird(pending, t, "spontaneous_FIN");
		}

	if ( tp->th_flags & TH_RST )
		{
		if ( ! (tp->th_flags & TH_SYN) )
			Weird(pending, t, "spontaneous_RST");
		}

	++sizes.pending_valid;
	++sizes.pending_total;
	++sizes.pending_in_mem;

	Event(pending, 0, new_connection,
		TCP_ENDPOINT_INACTIVE, 0, TCP_ENDPOINT_INACTIVE);

	if ( current_iosrc->GetCurrentTag() )
		{
		Val* tag =
			new StringVal(current_iosrc->GetCurrentTag()->c_str());
		Event(pending, 0, connection_external,
			TCP_ENDPOINT_INACTIVE, 0, TCP_ENDPOINT_INACTIVE, tag);
		}

	return 0;
	}

Connection* ConnCompressor::NextFromOrig(PendingConn* pending, double t,
						HashKey* key, const IP_Hdr* ip,
						const tcphdr* tp)
	{
	// Another packet from the same host without seeing an answer so far.
	DBG_LOG(DBG_COMPRESSOR, "%s same again", fmt_conn_id(pending));

	++pending->num_pkts;
	++pending->num_bytes_ip += ip->PayloadLen();

	// New window scale overrides old - not great, this is a (subtle)
	// evasion opportunity.
	if ( TCP_Analyzer::ParseTCPOptions(tp, parse_tcp_options, 0, 0,
						pending) < 0 )
		Weird(pending, t, "corrupt_tcp_options");

	if ( tp->th_flags & TH_SYN )
		// New seq overrides old.
		pending->seq = tp->th_seq;

	// Mimic TCP_Endpoint::Size()
	int size = ntohl(tp->th_seq) - ntohl(pending->seq);
	if ( size != 0 )
		--size;

	if ( size != 0 && (pending->FIN || (tp->th_flags & TH_FIN)) )
		--size;

	if ( size < 0 )
		// We only care about the size for broken connections.
		// Surely for those it's more likely that the sequence
		// numbers are confused than that they really transferred
		// > 2 GB of data.  Plus, for 64-bit ints these sign-extend
		// up to truly huge, non-sensical unsigned values.
		size = 0;

	if ( pending->SYN )
		{
		// We're in state SYN_SENT or SYN_ACK_SENT.
		if ( tp->th_flags & TH_RST)
			{
			Event(pending, t, connection_reset,
				TCP_ENDPOINT_RESET, size, TCP_ENDPOINT_INACTIVE);
			Event(pending, t, connection_state_remove,
				TCP_ENDPOINT_RESET, size, TCP_ENDPOINT_INACTIVE);

			Invalidate(key);
			return 0;
			}

		else if ( tp->th_flags & TH_FIN)
			{
			Event(pending, t, connection_partial_close,
				TCP_ENDPOINT_CLOSED, size, TCP_ENDPOINT_INACTIVE);
			Event(pending, t, connection_state_remove,
				TCP_ENDPOINT_CLOSED, size, TCP_ENDPOINT_INACTIVE);
			Invalidate(key);
			return 0;
			}

		else if ( tp->th_flags & TH_SYN )
			{
			if ( (tp->th_flags & TH_ACK) && ! pending->ACK )
				Weird(pending, t, "repeated_SYN_with_ack");
			}

		else
			{
			// A data packet without seeing a SYN/ACK first. As
			// long as we stick with the principle of instantiating
			// state only when we see a reply, we have to throw
			// this data away. Optionally we may instantiate a
			// real connection now.

			if ( cc_instantiate_on_data )
				return Instantiate(key, pending);
			// else
			//     Weird(pending, t, "data_without_SYN_ACK");
			}
		}

	else
		{ // We're in state INACTIVE.
		if ( tp->th_flags & TH_RST)
			{
			Event(pending, t, connection_reset,
				TCP_ENDPOINT_RESET, size, TCP_ENDPOINT_INACTIVE);
			Event(pending, t, connection_state_remove,
				TCP_ENDPOINT_RESET, size, TCP_ENDPOINT_INACTIVE);

			Invalidate(key);
			return 0;
			}

		else if ( tp->th_flags & TH_FIN)
			{
			Event(pending, t, connection_half_finished,
				TCP_ENDPOINT_CLOSED, size, TCP_ENDPOINT_INACTIVE);
			Event(pending, t, connection_state_remove,
				TCP_ENDPOINT_CLOSED, size, TCP_ENDPOINT_INACTIVE);

			Invalidate(key);
			return 0;
			}

		else if ( tp->th_flags & TH_SYN )
			{
			if ( ! tp->th_flags & TH_ACK )
				{
				Weird(pending, t, "SYN_after_partial");
				pending->SYN = 1;
				}
			}

		else
			// Another data packet. See discussion above.
			if ( cc_instantiate_on_data )
				return Instantiate(key, pending);

		// else
		//     Weird(pending, t, "data_without_SYN_ACK");
		}

	return 0;
	}

Connection* ConnCompressor::Response(PendingConn* pending, double t,
					HashKey* key, const IP_Hdr* ip,
					const tcphdr* tp)
	{
	// The packet comes from the former responder. That means we are
	// seeing a reply, so we are going to create a "real" connection now.
	DBG_LOG(DBG_COMPRESSOR, "%s response", fmt_conn_id(pending));

	// Optional: if it's a RST after SYN, we directly generate a
	// connection_rejected and throw the state away.
	if ( cc_handle_resets && (tp->th_flags & TH_RST) && pending->SYN )
		{
		// See discussion of size in DoExpire().
		DBG_LOG(DBG_COMPRESSOR, "%s reset", fmt_conn_id(pending));

		Event(pending, t, connection_reset,
			TCP_ENDPOINT_SYN_SENT, 0, TCP_ENDPOINT_RESET);
		Event(pending, t, connection_state_remove,
			TCP_ENDPOINT_SYN_SENT, 0, TCP_ENDPOINT_RESET);

		Invalidate(key);
		return 0;
		}

	// If a connection's initial packet is a RST, Bro's standard TCP
	// processing considers the connection done right away.  We simulate
	// this by instantiating a second connection in this case.  The
	// first one will time out eventually.
	if ( pending->RST && ! pending->SYN )
		{
		int orig_state =
			pending->RST ? TCP_ENDPOINT_RESET : TCP_ENDPOINT_CLOSED;
		Event(pending, 0, connection_attempt,
			  orig_state, 0, TCP_ENDPOINT_INACTIVE);
		Event(pending, 0, connection_state_remove,
			  orig_state, 0, TCP_ENDPOINT_INACTIVE);

		// Override with current packet.
		PktHdrToPendingConn(t, key, ip, tp, pending);
		return 0;
		}

	return Instantiate(key, pending);
	}

Connection* ConnCompressor::Instantiate(HashKey* key, PendingConn* pending)
	{
	// Instantantiate a Connection.
	ConnID conn_id;
	conn_id.src_addr = SrcAddr(pending);
	conn_id.dst_addr = DstAddr(pending);
	conn_id.src_port = SrcPort(pending);
	conn_id.dst_port = DstPort(pending);

	pending->invalid = 1;
	--sizes.pending_valid;
	--sizes.pending_total;

	// Fake the first packet.
	const IP_Hdr* faked_pkt = PendingConnToPacket(pending);
	Connection* new_conn = sessions->NewConn(key, pending->time, &conn_id,
			faked_pkt->Payload(), IPPROTO_TCP);

	if ( ! new_conn )
		{
		// This connection is not to be analyzed (e.g., it may be
		// a partial one).
		DBG_LOG(DBG_COMPRESSOR, "%s nop", fmt_conn_id(pending));
		return 0;
		}

	new_conn->SetUID(pending->uid);

	DBG_LOG(DBG_COMPRESSOR, "%s instantiated", fmt_conn_id(pending));

	++sizes.connections;
	++sizes.connections_total;

	if ( new_packet )
		new_conn->Event(new_packet, 0,
				sessions->BuildHeader(faked_pkt->IP4_Hdr()));

	// NewConn() may have swapped originator and responder.
	int is_orig = addr_eq(conn_id.src_addr, new_conn->OrigAddr()) &&
			conn_id.src_port == new_conn->OrigPort();

	// Pass the faked packet to the connection.
	const u_char* payload = faked_pkt->Payload();

	int dummy_record_packet, dummy_record_content;
	new_conn->NextPacket(pending->time, is_orig,
			faked_pkt, faked_pkt->PayloadLen(),
			faked_pkt->PayloadLen(), payload,
			dummy_record_packet, dummy_record_content, 0, 0, 0);

	// Removing necessary because the key will be destroyed at some point.
	conns.Remove(&pending->key, sizeof(pending->key), pending->hash, true);
	conns.Insert(key, MakeMapPtr(new_conn));

	return new_conn;
	}

Connection* ConnCompressor::Instantiate(double t, HashKey* key,
						const IP_Hdr* ip)
	{
	const struct tcphdr* tp = (const struct tcphdr*) ip->Payload();

	ConnID conn_id;
	conn_id.src_addr = ip->SrcAddr();
	conn_id.dst_addr = ip->DstAddr();
	conn_id.src_port = tp->th_sport;
	conn_id.dst_port = tp->th_dport;

	Connection* new_conn =
		sessions->NewConn(key, t, &conn_id, ip->Payload(), IPPROTO_TCP);

	if ( ! new_conn )
		{
		// This connection is not to be analyzed (e.g., it may be
		// a partial one).
		DBG_LOG(DBG_COMPRESSOR, "%s nop", fmt_conn_id(ip));
		return 0;
		}

	DBG_LOG(DBG_COMPRESSOR, "%s instantiated", fmt_conn_id(ip));

	conns.Insert(key, MakeMapPtr(new_conn));
	++sizes.connections;
	++sizes.connections_total;

	if ( new_connection )
		new_conn->Event(new_connection, 0);

	if ( current_iosrc->GetCurrentTag() )
		{
		Val* tag =
			new StringVal(current_iosrc->GetCurrentTag()->c_str());
		new_conn->Event(connection_external, 0, tag);
		}

	return new_conn;
	}

void ConnCompressor::PktHdrToPendingConn(double time, const HashKey* key,
		const IP_Hdr* ip, const struct tcphdr* tp, PendingConn* c)
	{
	memcpy(&c->key, key->Key(), key->Size());

	c->hash = key->Hash();
	c->ip1_is_src = addr_eq(c->key.ip1, ip->SrcAddr()) &&
			c->key.port1 == tp->th_sport;
	c->time = time;
	c->window = tp->th_win;
	c->seq = tp->th_seq;
	c->ack = tp->th_ack;
	c->window_scale = 0;
	c->SYN = (tp->th_flags & TH_SYN) != 0;
	c->FIN = (tp->th_flags & TH_FIN) != 0;
	c->RST = (tp->th_flags & TH_RST) != 0;
	c->ACK = (tp->th_flags & TH_ACK) != 0;
	c->uid = calculate_unique_id();
	c->num_bytes_ip = ip->TotalLen();
	c->num_pkts = 1;
	c->invalid = 0;

	if ( TCP_Analyzer::ParseTCPOptions(tp, parse_tcp_options, 0, 0, c) < 0 )
		sessions->Weird("corrupt_tcp_options", ip);
	}

// Fakes an empty TCP packet based on the information in PendingConn.
const IP_Hdr* ConnCompressor::PendingConnToPacket(const PendingConn* c)
	{
	static ip* ip = 0;
	static tcphdr* tp = 0;
	static IP_Hdr* ip_hdr = 0;

	if ( ! ip )
		{ // Initialize.  ### Note, only handles IPv4 for now.
		int packet_length = sizeof(*ip) + sizeof(*tp);
		ip = (struct ip*) new char[packet_length];
		tp = (struct tcphdr*) (((char*) ip) + sizeof(*ip));
		ip_hdr = new IP_Hdr(ip);

		// Constant fields.
		ip->ip_v = 4;
		ip->ip_hl = sizeof(*ip) / 4;	// no options
		ip->ip_tos = 0;
		ip->ip_len = htons(packet_length);
		ip->ip_id = 0;
		ip->ip_off = 0;
		ip->ip_ttl = 255;
		ip->ip_p = IPPROTO_TCP;
		ip->ip_sum = 0;	// is not going to be checked

		tp->th_off = sizeof(*tp) / 4;	// no options for now
		tp->th_urp = 0;
		}

	// Note, do *not* use copy_addr() here.  This is because we're
	// copying to an IPv4 header, which has room for exactly and
	// only an IPv4 address.
#ifdef BROv6
	if ( ! is_v4_addr(c->key.ip1) || ! is_v4_addr(c->key.ip2) )
		internal_error("IPv6 snuck into connection compressor");
#endif
	*(uint32*) &ip->ip_src =
			to_v4_addr(c->ip1_is_src ? c->key.ip1 : c->key.ip2);
	*(uint32*) &ip->ip_dst =
			to_v4_addr(c->ip1_is_src ? c->key.ip2 : c->key.ip1);

	if ( c->ip1_is_src )
		{
		tp->th_sport = c->key.port1;
		tp->th_dport = c->key.port2;
		}
	else
		{
		tp->th_sport = c->key.port2;
		tp->th_dport = c->key.port1;
		}

	tp->th_win = c->window;
	tp->th_seq = c->seq;
	tp->th_ack = c->ack;
	tp->th_flags = MakeFlags(c);
	tp->th_sum = 0;
	tp->th_sum = 0xffff - tcp_checksum(ip, tp, 0);

	// FIXME: Add TCP options.
	return ip_hdr;
	}

uint8 ConnCompressor::MakeFlags(const PendingConn* c) const
	{
	uint8 tcp_flags = 0;
	if ( c->SYN )
		tcp_flags |= TH_SYN;
	if ( c->FIN )
		tcp_flags |= TH_FIN;
	if ( c->RST )
		tcp_flags |= TH_RST;
	if ( c->ACK )
		tcp_flags |= TH_ACK;

	return tcp_flags;
	}

ConnCompressor::PendingConn* ConnCompressor::MakeNewState(double t)
	{
	// See if there is enough space in the current block.
	if ( last_block &&
	     int(sizeof(PendingConn)) <= BLOCK_SIZE - last_block->bytes_used )
		{
		PendingConn* c = (PendingConn*) &last_block->data[last_block->bytes_used];
		last_block->bytes_used += sizeof(PendingConn);
		c->is_pending = true;
		return c;
		}

	// Get new block.
	Block* b = new Block;
	b->time = t;
	b->bytes_used = sizeof(PendingConn);
	b->next = 0;
	b->prev = last_block;

	if ( last_block )
		last_block->next = b;
	else
		first_block = b;

	last_block = b;

	sizes.memory += padded_sizeof(*b);
	PendingConn* c = (PendingConn*) &b->data;
	c->is_pending = true;
	return c;
	}

void ConnCompressor::DoExpire(double t)
	{
	while ( first_block )
		{
		Block* b = first_block;

		unsigned char* p =
			first_non_expired ? first_non_expired : b->data;

		while ( p < b->data + b->bytes_used )
			{
			Unref(conn_val);
			conn_val = 0;

			PendingConn* c = (PendingConn*) p;
			if ( t && (c->time + tcp_SYN_timeout > t) )
				{
				// All following entries are still
				// recent enough.
				first_non_expired = p;
				return;
				}

			if ( ! c->invalid )
				{
				// Expired.
				DBG_LOG(DBG_COMPRESSOR, "%s expire", fmt_conn_id(c));

				HashKey key(&c->key, sizeof(c->key), c->hash, true);

				ConnData* cd = conns.Lookup(&key);
				if ( cd && ! IsConnPtr(cd) )
					conns.Remove(&c->key, sizeof(c->key),
							c->hash, true);

				int orig_state = TCP_ENDPOINT_INACTIVE;

				if ( c->FIN )
					orig_state = TCP_ENDPOINT_CLOSED;
				if ( c->RST )
					orig_state = TCP_ENDPOINT_RESET;
				if ( c->SYN )
					orig_state = TCP_ENDPOINT_SYN_SENT;

				// We're not able to get the correct size
				// here (with "correct" meaning value that
				// standard connection processing reports).
				// We could if would also store last_seq, but
				// doesn't seem worth it.

				Event(c, 0, connection_attempt,
					orig_state, 0, TCP_ENDPOINT_INACTIVE);
				Event(c, 0, connection_state_remove,
					orig_state, 0, TCP_ENDPOINT_INACTIVE);

				c->invalid = 1;
				--sizes.pending_valid;
				}

			p += sizeof(PendingConn);
			--sizes.pending_in_mem;
			}

		// Full block expired, so delete it.
		first_block = b->next;

		if ( b->next )
			b->next->prev = 0;
		else
			last_block = 0;

		delete b;

		first_non_expired = 0;
		sizes.memory -= padded_sizeof(*b);
		}
	}

void ConnCompressor::Event(const PendingConn* pending, double t,
				const EventHandlerPtr& event, int orig_state,
				int orig_size, int resp_state, Val* arg)
	{
	if ( ! conn_val )
		{
		if ( ! event )
			return;

		// We only raise events if NewConn() would have actually
		// instantiated the Connection.
		bool flip_roles;
		if ( ! sessions->WantConnection(ntohs(SrcPort(pending)),
						ntohs(DstPort(pending)),
						TRANSPORT_TCP,
						MakeFlags(pending),
						flip_roles) )
			return;

		conn_val = new RecordVal(connection_type);
		RecordVal* id_val = new RecordVal(conn_id);
		RecordVal* orig_endp = new RecordVal(endpoint);
		RecordVal* resp_endp = new RecordVal(endpoint);

		if ( orig_state == TCP_ENDPOINT_INACTIVE )
			{
			if ( pending->SYN )
				orig_state = pending->ACK ?
					TCP_ENDPOINT_SYN_ACK_SENT :
					TCP_ENDPOINT_SYN_SENT;
			else
				orig_state = TCP_ENDPOINT_PARTIAL;
			}

		int tcp_state = TCP_ENDPOINT_INACTIVE;

		if ( ! flip_roles )
			{
			id_val->Assign(0, new AddrVal(SrcAddr(pending)));
			id_val->Assign(1, new PortVal(ntohs(SrcPort(pending)),
							TRANSPORT_TCP));
			id_val->Assign(2, new AddrVal(DstAddr(pending)));
			id_val->Assign(3, new PortVal(ntohs(DstPort(pending)),
							TRANSPORT_TCP));
			orig_endp->Assign(0, new Val(orig_size, TYPE_COUNT));
			orig_endp->Assign(1, new Val(orig_state, TYPE_COUNT));

			if ( ConnSize_Analyzer::Available() )
				{
				orig_endp->Assign(2, new Val(pending->num_pkts, TYPE_COUNT));
				orig_endp->Assign(3, new Val(pending->num_bytes_ip, TYPE_COUNT));
				}
			else
				{
				orig_endp->Assign(2, new Val(0, TYPE_COUNT));
				orig_endp->Assign(3, new Val(0, TYPE_COUNT));
				}


			resp_endp->Assign(0, new Val(0, TYPE_COUNT));
			resp_endp->Assign(1, new Val(resp_state, TYPE_COUNT));
			resp_endp->Assign(2, new Val(0, TYPE_COUNT));
			resp_endp->Assign(3, new Val(0, TYPE_COUNT));
			}
		else
			{
			id_val->Assign(0, new AddrVal(DstAddr(pending)));
			id_val->Assign(1, new PortVal(ntohs(DstPort(pending)),
							TRANSPORT_TCP));
			id_val->Assign(2, new AddrVal(SrcAddr(pending)));
			id_val->Assign(3, new PortVal(ntohs(SrcPort(pending)),
							TRANSPORT_TCP));

			orig_endp->Assign(0, new Val(0, TYPE_COUNT));
			orig_endp->Assign(1, new Val(resp_state, TYPE_COUNT));
			orig_endp->Assign(2, new Val(0, TYPE_COUNT));
			orig_endp->Assign(3, new Val(0, TYPE_COUNT));

			resp_endp->Assign(0, new Val(orig_size, TYPE_COUNT));
			resp_endp->Assign(1, new Val(orig_state, TYPE_COUNT));

			if ( ConnSize_Analyzer::Available() )
				{
				resp_endp->Assign(2, new Val(pending->num_pkts, TYPE_COUNT));
				resp_endp->Assign(3, new Val(pending->num_bytes_ip, TYPE_COUNT));
				}
			else
				{
				resp_endp->Assign(2, new Val(0, TYPE_COUNT));
				resp_endp->Assign(3, new Val(0, TYPE_COUNT));
				}

			DBG_LOG(DBG_COMPRESSOR, "%s swapped direction", fmt_conn_id(pending));
			}

		conn_val->Assign(0, id_val);
		conn_val->Assign(1, orig_endp);
		conn_val->Assign(2, resp_endp);
		conn_val->Assign(3, new Val(pending->time, TYPE_TIME));
		conn_val->Assign(4, new Val(t > 0 ? t - pending->time : 0,
					TYPE_INTERVAL));	// duration
		conn_val->Assign(5, new TableVal(string_set));	// service
		conn_val->Assign(6, new StringVal("cc=1"));	// addl
		conn_val->Assign(7, new Val(0, TYPE_COUNT));	// hot
		conn_val->Assign(8, new StringVal(""));	// history

		char tmp[20]; // uid.
		conn_val->Assign(9, new StringVal(uitoa_n(pending->uid, tmp, sizeof(tmp), 62)));

		conn_val->SetOrigin(0);
		}

	val_list* vl = new val_list;
	if ( arg )
		vl->append(arg);
	vl->append(conn_val->Ref());

	mgr.QueueEvent(event, vl, SOURCE_LOCAL);
	}

void ConnCompressor::Drain()
	{
	IterCookie* cookie = conns.InitForIteration();
	ConnData* c;

	DoExpire(0);

	while ( (c = conns.NextEntry(cookie)) )
		{
		Unref(conn_val);
		conn_val = 0;

		if ( IsConnPtr(c) )
			{
			Connection* tc = MakeConnPtr(c);
			tc->Done();
			tc->Event(connection_state_remove, 0);
			Unref(tc);
			--sizes.connections;
			}

		else
			{
			PendingConn* pc = MakePendingConnPtr(c);
			if ( ! pc->invalid )
				{
				// Same discussion for size here than
				// in DoExpire().
				Event(pc, 0, connection_attempt,
					TCP_ENDPOINT_INACTIVE, 0,
					TCP_ENDPOINT_INACTIVE);
				Event(pc, 0, connection_state_remove,
					TCP_ENDPOINT_INACTIVE, 0,
					TCP_ENDPOINT_INACTIVE);

				--sizes.pending_valid;
				pc->invalid = 1;
				}
			}
		}
	}

void ConnCompressor::Invalidate(HashKey* k)
	{
	ConnData* c = (ConnData*) conns.Lookup(k);

	assert(c && ! IsConnPtr(c));
	PendingConn* pc = MakePendingConnPtr(c);

	DBG_LOG(DBG_COMPRESSOR, "%s invalidate", fmt_conn_id(pc));

	if ( ! pc->invalid )
		{
		conns.Remove(&pc->key, sizeof(pc->key), pc->hash, true);
		pc->invalid = 1;
		--sizes.pending_valid;
		}
	}

Connection* ConnCompressor::Insert(Connection* newconn)
	{
	HashKey* key = newconn->Key();
	ConnData* c = conns.Lookup(key);
	Connection* old = 0;

	// Do we already have a Connection object?
	if ( c )
		{
		if ( IsConnPtr(c) )
			old = MakeConnPtr(c);
		Remove(key);
		}

	conns.Insert(key, MakeMapPtr(newconn));
	return old;
	}

bool ConnCompressor::Remove(HashKey* k)
	{
	ConnData* c = (ConnData*) conns.Lookup(k);
	if ( ! c )
		return false;

	if ( IsConnPtr(c) )
		{
		DBG_LOG(DBG_COMPRESSOR, "%s remove", fmt_conn_id(MakeConnPtr(c)));
		conns.Remove(k);
		--sizes.connections;
		}
	else
		{
		PendingConn* pc = MakePendingConnPtr(c);
		DBG_LOG(DBG_COMPRESSOR, "%s remove", fmt_conn_id(pc));

		conns.Remove(&pc->key, sizeof(pc->key), pc->hash, true);

		if ( ! pc->invalid )
			{
			pc->invalid = 1;
			--sizes.pending_valid;
			}
		}

	return true;
	}
