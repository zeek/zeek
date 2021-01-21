// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/RuleMatcher.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/net_util.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(VectorVal, zeek);
namespace zeek {
using VectorValPtr = IntrusivePtr<VectorVal>;
}

namespace zeek::analyzer::icmp {

enum ICMP_EndpointState {
	ICMP_INACTIVE,	// no packet seen
	ICMP_ACTIVE,	// packets seen
};

// We do not have an PIA for ICMP (yet) and therefore derive from
// RuleMatcherState to perform our own matching.
class ICMP_Analyzer final : public analyzer::TransportLayerAnalyzer {
public:
	explicit ICMP_Analyzer(Connection* conn);

	void UpdateConnVal(RecordVal *conn_val) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new ICMP_Analyzer(conn); }

protected:
	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
	                   uint64_t seq, const IP_Hdr* ip, int caplen) override;
	bool IsReuse(double t, const u_char* pkt) override;
	unsigned int MemoryAllocation() const override;

	void ICMP_Sent(const struct icmp* icmpp, int len, int caplen, int icmpv6,
	               const u_char* data, const IP_Hdr* ip_hdr);

	void Echo(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const IP_Hdr* ip_hdr);
	void Redirect(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const IP_Hdr* ip_hdr);
	void RouterAdvert(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const IP_Hdr* ip_hdr);
	void NeighborAdvert(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const IP_Hdr* ip_hdr);
	void NeighborSolicit(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const IP_Hdr* ip_hdr);
	void RouterSolicit(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const IP_Hdr* ip_hdr);

	void Describe(ODesc* d) const;

	RecordValPtr BuildICMPVal(const struct icmp* icmpp, int len,
	                          int icmpv6, const IP_Hdr* ip_hdr);

	RecordValPtr BuildInfo(const struct icmp* icmpp, int len,
	                       bool icmpv6, const IP_Hdr* ip_hdr);

	void NextICMP4(double t, const struct icmp* icmpp, int len, int caplen,
	               const u_char*& data, const IP_Hdr* ip_hdr );

	RecordValPtr ExtractICMP4Context(int len, const u_char*& data);

	void Context4(double t, const struct icmp* icmpp, int len, int caplen,
	              const u_char*& data, const IP_Hdr* ip_hdr);

	TransportProto GetContextProtocol(const IP_Hdr* ip_hdr, uint32_t* src_port,
	                                  uint32_t* dst_port);

	void NextICMP6(double t, const struct icmp* icmpp, int len, int caplen,
	               const u_char*& data, const IP_Hdr* ip_hdr );

	RecordValPtr ExtractICMP6Context(int len, const u_char*& data);

	void Context6(double t, const struct icmp* icmpp, int len, int caplen,
	              const u_char*& data, const IP_Hdr* ip_hdr);

	// RFC 4861 Neighbor Discover message options
	VectorValPtr BuildNDOptionsVal(int caplen, const u_char* data);

	RecordValPtr icmp_conn_val;
	int type;
	int code;
	int request_len, reply_len;

	detail::RuleMatcherState matcher_state;

private:
	void UpdateEndpointVal(const ValPtr& endp, bool is_orig);
};

// Returns the counterpart type to the given type (e.g., the counterpart
// to ICMP_ECHOREPLY is ICMP_ECHO).
extern int ICMP4_counterpart(int icmp_type, int icmp_code, bool& is_one_way);
extern int ICMP6_counterpart(int icmp_type, int icmp_code, bool& is_one_way);

} // namespace zeek::analyzer::icmp
