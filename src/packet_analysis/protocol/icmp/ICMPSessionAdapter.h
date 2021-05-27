// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"
#include "zeek/RuleMatcher.h"

namespace zeek::packet_analysis::ICMP {

class ICMPSessionAdapter final : public IP::SessionAdapter {

public:

	ICMPSessionAdapter(Connection* conn) :
		IP::SessionAdapter("ICMP", conn) { }

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{
		return new ICMPSessionAdapter(conn);
		}

	void AddExtraAnalyzers(Connection* conn) override;
	void UpdateConnVal(RecordVal* conn_val) override;
	void UpdateEndpointVal(const ValPtr& endp, bool is_orig);

	void UpdateLength(bool is_orig, int len);
	void Done() override;

	void InitEndpointMatcher(const IP_Hdr* ip_hdr, int len, bool is_orig);
	void MatchEndpoint(const u_char* data, int len, bool is_orig);

private:

	detail::RuleMatcherState matcher_state;
	int request_len = -1;
	int reply_len = -1;
};

} // namespace zeek::packet_analysis::ICMP
