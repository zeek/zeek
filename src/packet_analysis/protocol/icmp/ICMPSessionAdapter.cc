// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/icmp/ICMPSessionAdapter.h"

#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/conn-size/ConnSize.h"

using namespace zeek::packet_analysis::ICMP;
using namespace zeek::packet_analysis::IP;

enum ICMP_EndpointState {
	ICMP_INACTIVE,	// no packet seen
	ICMP_ACTIVE,	// packets seen
};

void ICMPSessionAdapter::AddExtraAnalyzers(Connection* conn)
	{
	static analyzer::Tag analyzer_connsize = analyzer_mgr->GetComponentTag("CONNSIZE");

	if ( analyzer_mgr->IsEnabled(analyzer_connsize) )
		// Add ConnSize analyzer. Needs to see packets, not stream.
		AddChildAnalyzer(new analyzer::conn_size::ConnSize_Analyzer(conn));
	}

void ICMPSessionAdapter::UpdateConnVal(zeek::RecordVal* conn_val)
	{
	const auto& orig_endp = conn_val->GetField("orig");
	const auto& resp_endp = conn_val->GetField("resp");

	UpdateEndpointVal(orig_endp, true);
	UpdateEndpointVal(resp_endp, false);

	analyzer::Analyzer::UpdateConnVal(conn_val);
	}

void ICMPSessionAdapter::UpdateEndpointVal(const ValPtr& endp_arg, bool is_orig)
	{
	Conn()->EnableStatusUpdateTimer();

	int size = is_orig ? request_len : reply_len;
	auto endp = endp_arg->AsRecordVal();

	if ( size < 0 )
		{
		endp->Assign(0, val_mgr->Count(0));
		endp->Assign(1, val_mgr->Count(int(ICMP_INACTIVE)));
		}
	else
		{
		endp->Assign(0, val_mgr->Count(size));
		endp->Assign(1, val_mgr->Count(int(ICMP_ACTIVE)));
		}
	}

void ICMPSessionAdapter::UpdateLength(bool is_orig, int len)
	{
	int& len_stat = is_orig ? request_len : reply_len;
	if ( len_stat < 0 )
		len_stat = len;
	else
		len_stat += len;
	}

void ICMPSessionAdapter::InitEndpointMatcher(const IP_Hdr* ip_hdr, int len, bool is_orig)
	{
	if ( zeek::detail::rule_matcher )
		{
		if ( ! matcher_state.MatcherInitialized(is_orig) )
			matcher_state.InitEndpointMatcher(this, ip_hdr, len, is_orig, nullptr);
		}
	}

void ICMPSessionAdapter::MatchEndpoint(const u_char* data, int len, bool is_orig)
	{
	if ( zeek::detail::rule_matcher )
		matcher_state.Match(zeek::detail::Rule::PAYLOAD, data, len, is_orig,
		                    false, false, true);
	}

void ICMPSessionAdapter::Done()
	{
	SessionAdapter::Done();
	matcher_state.FinishEndpointMatcher();
	}
