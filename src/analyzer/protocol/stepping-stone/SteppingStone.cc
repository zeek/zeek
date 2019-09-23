// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

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

	CreateEndpEvent(e->IsOrig());

	// Make sure the connection does not get deleted.
	Ref(endp->TCP()->Conn());
	}

SteppingStoneEndpoint::~SteppingStoneEndpoint()
	{
	Unref(endp->TCP()->Conn());
	}

void SteppingStoneEndpoint::Done()
	{
	if ( RefCnt() > 1 )
		return;

	SteppingStoneEndpoint* ep;

	for ( const auto& entry : stp_inbound_endps )
		{
		ep = entry.second;
		ep->stp_outbound_endps.erase(stp_id);
		Event(stp_remove_pair, ep->stp_id, stp_id);
		Unref(ep);
		}

	for ( const auto& entry : stp_outbound_endps )
		{
		ep = entry.second;
		ep->stp_inbound_endps.erase(stp_id);
		Event(stp_remove_pair, stp_id, ep->stp_id);
		Unref(ep);
		}

	Event(stp_remove_endp, stp_id);
	}

int SteppingStoneEndpoint::DataSent(double t, uint64_t seq, int len, int caplen,
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
	    auto e = stp_manager->OrderedEndpoints().front();

		if ( e->stp_resume_time < tmin )
			{
			stp_manager->OrderedEndpoints().pop_front();
			e->Done();
			Unref(e);
			}
		else
			break;
		}

	uint64_t ack = endp->ToRelativeSeqSpace(endp->AckSeq(), endp->AckWraps());
	uint64_t top_seq = seq + len;

	if ( top_seq <= ack || top_seq <= stp_max_top_seq )
		// There is no new data in this packet
		return 0;

	stp_max_top_seq = top_seq;

	if ( stp_last_time != 0.0 && t <= stp_last_time + stp_idle_min )
		{
		stp_last_time = t;
		return 1;
		}

	// Either just starts, or resumes from an idle period.
	stp_last_time = stp_resume_time = t;

	Event(stp_resume_endp, stp_id);
	for ( auto ep : stp_manager->OrderedEndpoints() )
		{
		if ( ep->endp->TCP() != endp->TCP() )
			{
			Ref(ep);
			Ref(this);

			stp_inbound_endps[ep->stp_id] = ep;
			ep->stp_outbound_endps[stp_id] = this;

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

	if ( id2 >= 0 )
		endp->TCP()->ConnectionEventFast(f, {val_mgr->GetInt(id1), val_mgr->GetInt(id2)});
	else
		endp->TCP()->ConnectionEventFast(f, {val_mgr->GetInt(id1)});

	}

void SteppingStoneEndpoint::CreateEndpEvent(int is_orig)
	{
	if ( ! stp_create_endp )
		return;

	endp->TCP()->ConnectionEventFast(stp_create_endp, {
		endp->TCP()->BuildConnVal(),
		val_mgr->GetInt(stp_id),
		val_mgr->GetBool(is_orig),
	});
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

void SteppingStone_Analyzer::DeliverPacket(uint64_t len, const u_char* data,
						bool is_orig, uint64_t seq,
						const IP_Hdr* ip, uint64_t caplen)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverPacket(len, data, is_orig, seq,
						ip, caplen);

	if ( is_orig )
		orig_endp->DataSent(network_time, seq, len, caplen, data, 0, 0);
	else
		resp_endp->DataSent(network_time, seq, len, caplen, data, 0, 0);
	}

void SteppingStone_Analyzer::DeliverStream(uint64_t len, const u_char* data,
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
