// See the file "COPYING" in the main distribution directory for copyright.

#include "ConnExtInfoAnalyzer.h"
#include "TCP.h"

ConnExtInfo_Endpoint::ConnExtInfo_Endpoint()
	{
	init_common_members();
	}

void ConnExtInfo_Endpoint::init_common_members()
	{
	peer = 0;
	RTT = 0.0;
	MSS = 0;
	SACK_OK = 0;
	SACK_used =0;
	wscale = -1;
	wscale_negotiated = false;
	ts_opt_used = false;
	maxwin = 0;
	minwin = 0;
	syns = 0;
	ttl_changed = false;
	first_pkt_ttl =0;

	last_seq = 0;
	didrst = false;
	}

ConnExtInfo_Endpoint::~ConnExtInfo_Endpoint() 
	{
	}

int ConnExtInfo_Endpoint::AddPacket(int arg_ip_bytes, int ttl)
	{
	ip_bytes += arg_ip_bytes;
	num_pkts++;
	if (num_pkts == 1)
		first_pkt_ttl = ttl;
	else if (num_pkts == 2 && first_pkt_ttl!=ttl) 
		ttl_changed = true;

	return 0;
	}

void ConnExtInfo_Endpoint::UpdateWindow(int window)
	{
	if (wscale_negotiated && wscale>=0)
		window = window << wscale;
	if (maxwin == 0 && minwin==0)
		maxwin = minwin = window;
	else 
		{
		maxwin = max(maxwin, window);
		minwin = min(minwin, window);
		}
	}

RecordVal* ConnExtInfo_Endpoint::GetRecordVal()
	{
	RecordVal* rv = new RecordVal(BifType::Record::EndpointExtInfo);
	rv->Assign(0, new Val(MSS,TYPE_COUNT));
	rv->Assign(1, new Val(SACK_OK,TYPE_BOOL));
	rv->Assign(2, new Val(SACK_used,TYPE_COUNT));
	rv->Assign(3, new Val(wscale,TYPE_INT));
	rv->Assign(4, new Val(ts_opt_used,TYPE_BOOL));
	rv->Assign(5, new Val(maxwin,TYPE_COUNT));
	rv->Assign(6, new Val(minwin,TYPE_COUNT));
	rv->Assign(7, new Val(RTT,TYPE_INTERVAL));
	rv->Assign(8, new Val(syns,TYPE_COUNT));
	rv->Assign(9, new Val(pkts_below_seq,TYPE_COUNT));
	// we currently don't use bytes_below_seq
	rv->Assign(10, new Val(first_pkt_ttl,TYPE_COUNT));
	rv->Assign(11, new Val(ttl_changed,TYPE_BOOL));

	return rv;
	}

ConnExtInfo_Analyzer::ConnExtInfo_Analyzer(Connection* c)
: Analyzer(AnalyzerTag::ConnExtInfo, c)
	{
	}

ConnExtInfo_Analyzer::~ConnExtInfo_Analyzer()
	{
	delete orig_info;
	delete resp_info;
	}

void ConnExtInfo_Analyzer::Init()
	{
	Analyzer::Init();

	orig_info = new ConnExtInfo_Endpoint();
	resp_info = new ConnExtInfo_Endpoint();

	orig_info->peer = resp_info;
	resp_info->peer = orig_info;
	state = STATE_INACTIVE;
	t_syn = t_synack = t_ack = 0.0;
	}

void ConnExtInfo_Analyzer::Done()
	{
	Analyzer::Done();
	}

void ConnExtInfo_Analyzer::DeliverPacket(int len, const u_char* data, bool is_orig, int seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);
	// NB: data and len point to TCP/UDP payload
	const struct tcphdr* tp = 0;
	int ip_bytes=0;

	ip_bytes = ip->TotalLen();
	if ( is_orig )
		orig_info->AddPacket(ip_bytes, (unsigned)ip->TTL());
	else
		resp_info->AddPacket(ip_bytes, (unsigned)ip->TTL());

	if (ip->NextProto() == IPPROTO_TCP) 
		{
		int pload_bytes;
		tp = (struct tcphdr *)(ip->Payload());
		pload_bytes = ip->PayloadLen() - tp->th_off*4;
		TCP_Packet(tp, is_orig, pload_bytes);
		}
	}

void ConnExtInfo_Analyzer::TCP_Packet(const struct tcphdr *tp, bool is_orig, int len) 
	{
	TCP_Flags flags(tp);
	ConnExtInfo_Endpoint *endp;
	ConnExtInfoState nextstate;
	uint32_t first_seq, last_seq;

	if ( is_orig )
		endp = orig_info;
	else
		endp = resp_info;

	/* Simpified TCP handshake state machine. Only transition if pure SYN. SYNACK, ACK
	 * handshake without retransmits, reodering,whatever. 
	 * If it's anything else, we go to STATE_OTHER
	 */
	nextstate = STATE_OTHER; 
	switch (state)
		{
		case STATE_INACTIVE:
			if (flags.SYN() && !flags.ACK() && !flags.FIN()  && !flags.RST() && is_orig)
				nextstate = STATE_SYN;
			break;
		case STATE_SYN:
			if (flags.SYN() && flags.ACK() && !flags.FIN()  && !flags.RST() && !is_orig)
				nextstate = STATE_SYNACK;
			break;
		case STATE_SYNACK:
			if (!flags.SYN() && flags.ACK() && !flags.FIN()  && !flags.RST() && is_orig) 
				{
				nextstate = STATE_ESTABLISHED;
				}
			break;
		case STATE_ESTABLISHED:
			// some connections see late (delay) duplicate SYNs, so
			// go to OTHER state if we see another SYN
			if (! flags.SYN()) 
				nextstate = STATE_ESTABLISHED;
			break;
		default:
			break;
		}

	// Handle anything that relies on the state of BOTH sides (is scaling negotiated, etc
	if (state == STATE_INACTIVE && nextstate == STATE_SYN)
		{  // the first syn packet
		t_syn = current_timestamp; 
		}
	else if (state == STATE_SYN && nextstate == STATE_SYNACK)
		{ // the syn-ack
		t_synack = current_timestamp; 
		resp_info->RTT = t_synack - t_syn;
		}
	else if (state == STATE_SYNACK && nextstate == STATE_ESTABLISHED)
		{ // the final ack
		t_ack = current_timestamp; 
		orig_info->RTT = t_ack - t_synack;
		}
	else if ( nextstate == STATE_OTHER) 
		orig_info->RTT = resp_info->RTT=0.0;

	// Update window
	// We do this before we parse the option, so we can use wscale_negotiated
	if (!flags.RST())
		endp->UpdateWindow(ntohs(tp->th_win));

	if (flags.SYN())
		{
		endp->syns++;
		len++; // SYNs take up 1 byte of seq space. 
		}

	if (flags.FIN())
		len++; // FINs take up 1 byte of seq space.

	first_seq = ntohl(tp->th_seq);
	last_seq = first_seq + len;

	if (flags.RST())
		endp->didrst = true;

	// Update sequence numbers and look for below sequence segments
	// This is simplified but good enough for our purpose
	if (endp->num_pkts<=1)
		endp->last_seq = last_seq;
	else if (!endp->didrst)
		{
		int delta = seq_delta(last_seq, endp->last_seq);
		if (delta > 0 || flags.FIN())
			// in order. update endpoint
			endp->last_seq += last_seq;
		else if ( delta <= 0 && len>0 )
			{  // a below sequence, unless it was a pure ACK
			if ( len>1 || !BifConst::ignore_keep_alive_rexmit )
				{
				endp->pkts_below_seq++;
				endp->bytes_below_seq += len;
				}
			}
		}

	// Parse TCP options.
	u_char* options = (u_char*) tp + sizeof(struct tcphdr);
	u_char* opt_end = (u_char*) tp + tp->th_off * 4;

	while ( options < opt_end )
		{
		unsigned int opt = options[0];

		if ( opt == TCPOPT_EOL )
			// All done - could flag if more junk left over ....
			break;

		if ( opt == TCPOPT_NOP )
			{
			++options;
			continue;
			}

		if ( options + 1 >= opt_end )
			// We've run off the end, no room for the length.
			break;

		unsigned int opt_len = options[1];

		if ( options + opt_len > opt_end )
			// No room for rest of option.
			break;

		if ( opt_len == 0 )
			// Trashed length field.
			break;

		switch ( opt ) {
		case TCPOPT_SACK_PERMITTED:
			endp->SACK_OK = 1;
			if (!flags.SYN())
				Weird("GMM. SACK_OK option on non SYN");
			break;

		case TCPOPT_MAXSEG:
			if ( opt_len < 4 )
				break;	// bad length
			endp->MSS = (options[2] << 8) | options[3];
			if (!flags.SYN())
				Weird("GMM. MSS option on non SYN");
			break;

		case 3: // TCPOPT_WINDOW (scale)
			if ( opt_len < 3 )
				break;	// bad length
			endp->wscale = options[2];
			if (endp->peer->wscale >= 0) 
				endp->wscale_negotiated = endp->peer->wscale_negotiated = true;
			if (!flags.SYN())
				Weird("GMM. WSCALE option on non SYN");
			break;

		case TCPOPT_SACK:
			if ( opt_len < 4) 
				break; // bad length 
			endp->SACK_used++;
			break;

		case TCPOPT_TIMESTAMP:
			if ( opt_len < 10 )
				break; // bad length 
			endp->ts_opt_used = true;
			break;

		default:	// just skip over
			break;
		}

		options += opt_len;
		}


	state = nextstate;
	}

void ConnExtInfo_Analyzer::UpdateConnVal(RecordVal *conn_val)
	{
	// RecordType *connection_type is decleared in NetVar.h
	int orig_endp_idx = connection_type->FieldOffset("orig");
	int resp_endp_idx = connection_type->FieldOffset("resp");
	RecordVal *orig_endp = conn_val->Lookup(orig_endp_idx)->AsRecordVal();
	RecordVal *resp_endp = conn_val->Lookup(resp_endp_idx)->AsRecordVal();

	// endpoint is the RecordType from NetVar.h
	int ext_info_idx = endpoint->FieldOffset("ext_info");

	orig_endp->Assign(ext_info_idx, orig_info->GetRecordVal());
	resp_endp->Assign(ext_info_idx, resp_info->GetRecordVal());

	// Update for children
	Analyzer::UpdateConnVal(conn_val);
	}

void ConnExtInfo_Analyzer::FlipRoles()
	{
	Analyzer::FlipRoles();
	ConnExtInfo_Endpoint *tmp;

	tmp = orig_info;
	orig_info = resp_info;
	resp_info = tmp;
	}

