// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <stdlib.h>

#include "Event.h"
#include "Net.h"
#include "NetVar.h"
#include "analyzer/protocol/tcp/TCP.h"
#include "SteppingStone.h"
#include "util.h"

#include "events.bif.h"

using namespace analyzer::stepping_stone;

SteppingStoneEndpoint::SteppingStoneEndpoint(tcp::TCP_Endpoint* e, SteppingStoneManager* m)
	{
	endp = e;
	stp_max_top_seq = 0;
	stp_last_time = stp_resume_time = 0.0;
	stp_manager = m;
	stp_id = stp_manager->NextID();
	stp_key = new HashKey(bro_int_t(stp_id));

	CreateEndpEvent(e->IsOrig());

	// Make sure the connection does not get deleted.
	Ref(endp->TCP()->Conn());
	}

SteppingStoneEndpoint::~SteppingStoneEndpoint()
	{
	delete stp_key;
	Unref(endp->TCP()->Conn());
	}

void SteppingStoneEndpoint::Done()
	{
	if ( RefCnt() > 1 )
		return;

	SteppingStoneEndpoint* ep;
	IterCookie* cookie;

	cookie = stp_inbound_endps.InitForIteration();
	while ( (ep = stp_inbound_endps.NextEntry(cookie)) )
		{
		ep->stp_outbound_endps.Remove(stp_key);
		Event(stp_remove_pair, ep->stp_id, stp_id);
		Unref(ep);
		}

	cookie = stp_outbound_endps.InitForIteration();
	while ( (ep = stp_outbound_endps.NextEntry(cookie)) )
		{
		ep->stp_inbound_endps.Remove(stp_key);
		Event(stp_remove_pair, stp_id, ep->stp_id);
		Unref(ep);
		}

	Event(stp_remove_endp, stp_id);
	}

int SteppingStoneEndpoint::DataSent(double t, int seq, int len, int caplen,
		const u_char* data, const IP_Hdr* /* ip */,
		const struct tcphdr* tp)
	{
	if ( caplen < len )
		len = caplen;

	if ( len <= 0 )
		return 0;

	double tmin = t - stp_delta;

	while ( stp_manager->OrderedEndpoints().length() > 0 )
		{
		int f = stp_manager->OrderedEndpoints().front();

		if ( stp_manager->OrderedEndpoints()[f]->stp_resume_time < tmin )
			{
			SteppingStoneEndpoint* e =
				stp_manager->OrderedEndpoints().pop_front();
			e->Done();
			Unref(e);
			}
		else
			break;
		}

	int ack = endp->AckSeq() - endp->StartSeq();
	int top_seq = seq + len;

	if ( top_seq <= ack || top_seq <= stp_max_top_seq )
		// There is no new data in this packet
		return 0;

	stp_max_top_seq = top_seq;

	if ( stp_last_time && t <= stp_last_time + stp_idle_min )
		{
		stp_last_time = t;
		return 1;
		}

	// Either just starts, or resumes from an idle period.
	stp_last_time = stp_resume_time = t;

	Event(stp_resume_endp, stp_id);
	loop_over_queue(stp_manager->OrderedEndpoints(), i)
		{
		SteppingStoneEndpoint* ep = stp_manager->OrderedEndpoints()[i];
		if ( ep->endp->TCP() != endp->TCP() )
			{
			Ref(ep);
			Ref(this);

			stp_inbound_endps.Insert(ep->stp_key, ep);
			ep->stp_outbound_endps.Insert(stp_key, this);

			Event(stp_correlate_pair, ep->stp_id, stp_id);
			}

		else
			{ // ep and this belong to same connection
			}
		}

	stp_manager->OrderedEndpoints().push_back(this);
	Ref(this);

	return 1;
	}

void SteppingStoneEndpoint::Event(EventHandlerPtr f, int id1, int id2)
	{
	if ( ! f )
		return;

	val_list* vl = new val_list;

	vl->append(new Val(id1, TYPE_INT));

	if ( id2 >= 0 )
		vl->append(new Val(id2, TYPE_INT));

	endp->TCP()->ConnectionEvent(f, vl);
	}

void SteppingStoneEndpoint::CreateEndpEvent(int is_orig)
	{
	val_list* vl = new val_list;

	vl->append(endp->TCP()->BuildConnVal());
	vl->append(new Val(stp_id, TYPE_INT));
	vl->append(new Val(is_orig, TYPE_BOOL));

	endp->TCP()->ConnectionEvent(stp_create_endp, vl);
	}

SteppingStone_Analyzer::SteppingStone_Analyzer(Connection* c)
: tcp::TCP_ApplicationAnalyzer("STEPPINGSTONE", c)
	{
	stp_manager = sessions->GetSTPManager();

	orig_endp = resp_endp = 0;
	orig_stream_pos = resp_stream_pos = 1;
	}

void SteppingStone_Analyzer::Init()
	{
	tcp::TCP_ApplicationAnalyzer::Init();

	assert(TCP());
	orig_endp = new SteppingStoneEndpoint(TCP()->Orig(), stp_manager);
	resp_endp = new SteppingStoneEndpoint(TCP()->Resp(), stp_manager);
	}

void SteppingStone_Analyzer::DeliverPacket(int len, const u_char* data,
						bool is_orig, int seq,
						const IP_Hdr* ip, int caplen)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverPacket(len, data, is_orig, seq,
						ip, caplen);

	if ( is_orig )
		orig_endp->DataSent(network_time, seq, len, caplen, data, 0, 0);
	else
		resp_endp->DataSent(network_time, seq, len, caplen, data, 0, 0);
	}

void SteppingStone_Analyzer::DeliverStream(int len, const u_char* data,
						bool is_orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, is_orig);

	if ( is_orig )
		{
		orig_endp->DataSent(network_time, orig_stream_pos, len, len,
					data, 0, 0);
		orig_stream_pos += len;
		}

	else
		{
		resp_endp->DataSent(network_time, resp_stream_pos, len, len,
					data, 0, 0);
		resp_stream_pos += len;
		}
	}

void SteppingStone_Analyzer::Done()
	{
	tcp::TCP_ApplicationAnalyzer::Done();

	orig_endp->Done();
	resp_endp->Done();

	Unref(orig_endp);
	Unref(resp_endp);
	}
