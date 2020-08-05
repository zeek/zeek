// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "SteppingStone.h"

#include <stdlib.h>

#include "Event.h"
#include "Net.h"
#include "NetVar.h"
#include "analyzer/protocol/tcp/TCP.h"
#include "Sessions.h"
#include "util.h"
#include "events.bif.h"

namespace zeek::analyzer::stepping_stone {

SteppingStoneEndpoint::SteppingStoneEndpoint(zeek::analyzer::tcp::TCP_Endpoint* e, SteppingStoneManager* m)
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

bool SteppingStoneEndpoint::DataSent(double t, uint64_t seq, int len, int caplen,
                                     const u_char* data, const zeek::IP_Hdr* /* ip */,
                                     const struct tcphdr* tp)
	{
	if ( caplen < len )
		len = caplen;

	if ( len <= 0 )
		return false;

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
		return false;

	stp_max_top_seq = top_seq;

	if ( stp_last_time && t <= stp_last_time + stp_idle_min )
		{
		stp_last_time = t;
		return true;
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

	return true;
	}

void SteppingStoneEndpoint::Event(zeek::EventHandlerPtr f, int id1, int id2)
	{
	if ( ! f )
		return;

	if ( id2 >= 0 )
		endp->TCP()->EnqueueConnEvent(f, zeek::val_mgr->Int(id1), zeek::val_mgr->Int(id2));
	else
		endp->TCP()->EnqueueConnEvent(f, zeek::val_mgr->Int(id1));
	}

void SteppingStoneEndpoint::CreateEndpEvent(bool is_orig)
	{
	if ( ! stp_create_endp )
		return;

	endp->TCP()->EnqueueConnEvent(stp_create_endp,
		endp->TCP()->ConnVal(),
		zeek::val_mgr->Int(stp_id),
		zeek::val_mgr->Bool(is_orig)
	);
	}

SteppingStone_Analyzer::SteppingStone_Analyzer(zeek::Connection* c)
	: zeek::analyzer::tcp::TCP_ApplicationAnalyzer("STEPPINGSTONE", c)
	{
	stp_manager = zeek::sessions->GetSTPManager();

	orig_endp = resp_endp = nullptr;
	orig_stream_pos = resp_stream_pos = 1;
	}

void SteppingStone_Analyzer::Init()
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Init();

	assert(TCP());
	orig_endp = new SteppingStoneEndpoint(TCP()->Orig(), stp_manager);
	resp_endp = new SteppingStoneEndpoint(TCP()->Resp(), stp_manager);
	}

void SteppingStone_Analyzer::DeliverPacket(int len, const u_char* data,
                                           bool is_orig, uint64_t seq,
                                           const zeek::IP_Hdr* ip, int caplen)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::DeliverPacket(len, data, is_orig, seq,
	                                                            ip, caplen);

	if ( is_orig )
		orig_endp->DataSent(zeek::net::network_time, seq, len, caplen, data, nullptr, nullptr);
	else
		resp_endp->DataSent(zeek::net::network_time, seq, len, caplen, data, nullptr, nullptr);
	}

void SteppingStone_Analyzer::DeliverStream(int len, const u_char* data,
                                           bool is_orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, is_orig);

	if ( is_orig )
		{
		orig_endp->DataSent(zeek::net::network_time, orig_stream_pos, len, len,
		                    data, nullptr, nullptr);
		orig_stream_pos += len;
		}

	else
		{
		resp_endp->DataSent(zeek::net::network_time, resp_stream_pos, len, len,
		                    data, nullptr, nullptr);
		resp_stream_pos += len;
		}
	}

void SteppingStone_Analyzer::Done()
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	orig_endp->Done();
	resp_endp->Done();

	Unref(orig_endp);
	Unref(resp_endp);
	}

} // namespace zeek::analyzer::stepping_stone
