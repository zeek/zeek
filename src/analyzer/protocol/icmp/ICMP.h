// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "RuleMatcher.h"
#include "analyzer/Analyzer.h"
#include "net_util.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(VectorVal, zeek);
namespace zeek {
using VectorValPtr = zeek::IntrusivePtr<VectorVal>;
}

namespace zeek::analyzer::icmp {

enum ICMP_EndpointState {
	ICMP_INACTIVE,	// no packet seen
	ICMP_ACTIVE,	// packets seen
};

// We do not have an PIA for ICMP (yet) and therefore derive from
// RuleMatcherState to perform our own matching.
class ICMP_Analyzer final : public zeek::analyzer::TransportLayerAnalyzer {
public:
	explicit ICMP_Analyzer(zeek::Connection* conn);

	void UpdateConnVal(zeek::RecordVal *conn_val) override;

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new ICMP_Analyzer(conn); }

protected:
	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
	                   uint64_t seq, const zeek::IP_Hdr* ip, int caplen) override;
	bool IsReuse(double t, const u_char* pkt) override;
	unsigned int MemoryAllocation() const override;

	void ICMP_Sent(const struct icmp* icmpp, int len, int caplen, int icmpv6,
	               const u_char* data, const zeek::IP_Hdr* ip_hdr);

	void Echo(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const zeek::IP_Hdr* ip_hdr);
	void Redirect(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const zeek::IP_Hdr* ip_hdr);
	void RouterAdvert(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const zeek::IP_Hdr* ip_hdr);
	void NeighborAdvert(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const zeek::IP_Hdr* ip_hdr);
	void NeighborSolicit(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const zeek::IP_Hdr* ip_hdr);
	void RouterSolicit(double t, const struct icmp* icmpp, int len,
			 int caplen, const u_char*& data, const zeek::IP_Hdr* ip_hdr);

	void Describe(zeek::ODesc* d) const;

	zeek::RecordValPtr BuildICMPVal(const struct icmp* icmpp, int len,
	                                int icmpv6, const zeek::IP_Hdr* ip_hdr);

	zeek::RecordValPtr BuildInfo(const struct icmp* icmpp, int len,
	                             bool icmpv6, const zeek::IP_Hdr* ip_hdr);

	void NextICMP4(double t, const struct icmp* icmpp, int len, int caplen,
	               const u_char*& data, const zeek::IP_Hdr* ip_hdr );

	zeek::RecordValPtr ExtractICMP4Context(int len, const u_char*& data);

	void Context4(double t, const struct icmp* icmpp, int len, int caplen,
	              const u_char*& data, const zeek::IP_Hdr* ip_hdr);

	TransportProto GetContextProtocol(const zeek::IP_Hdr* ip_hdr, uint32_t* src_port,
	                                  uint32_t* dst_port);

	void NextICMP6(double t, const struct icmp* icmpp, int len, int caplen,
	               const u_char*& data, const zeek::IP_Hdr* ip_hdr );

	zeek::RecordValPtr ExtractICMP6Context(int len, const u_char*& data);

	void Context6(double t, const struct icmp* icmpp, int len, int caplen,
	              const u_char*& data, const zeek::IP_Hdr* ip_hdr);

	// RFC 4861 Neighbor Discover message options
	zeek::VectorValPtr BuildNDOptionsVal(int caplen, const u_char* data);

	zeek::RecordValPtr icmp_conn_val;
	int type;
	int code;
	int request_len, reply_len;

	zeek::detail::RuleMatcherState matcher_state;

private:
	void UpdateEndpointVal(const zeek::ValPtr& endp, bool is_orig);
};

// Returns the counterpart type to the given type (e.g., the counterpart
// to ICMP_ECHOREPLY is ICMP_ECHO).
extern int ICMP4_counterpart(int icmp_type, int icmp_code, bool& is_one_way);
extern int ICMP6_counterpart(int icmp_type, int icmp_code, bool& is_one_way);

} // namespace zeek::analyzer::icmp

namespace analyzer::icmp {

	using ICMP_EndpointState [[deprecated("Remove in v4.1. Use zeek::analyzer::icmp::ICMP_EndpointState.")]] = zeek::analyzer::icmp::ICMP_EndpointState;
	constexpr auto ICMP_INACTIVE [[deprecated("Remove in v4.1. Use zeek::analyzer::icmp::ICMP_INACTIVE.")]] = zeek::analyzer::icmp::ICMP_INACTIVE;
	constexpr auto ICMP_ACTIVE [[deprecated("Remove in v4.1. Use zeek::analyzer::icmp::ICMP_ACTIVE.")]] = zeek::analyzer::icmp::ICMP_ACTIVE;

	using ICMP_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::icmp::ICMP_Analyzer.")]] = zeek::analyzer::icmp::ICMP_Analyzer;

	constexpr auto ICMP4_counterpart [[deprecated("Remove in v4.1. Use zeek::analyzer::icmp::ICMP4_counterpart.")]] = zeek::analyzer::icmp::ICMP4_counterpart;
	constexpr auto ICMP6_counterpart [[deprecated("Remove in v6.1. Use zeek::analyzer::icmp::ICMP6_counterpart.")]] = zeek::analyzer::icmp::ICMP6_counterpart;

} // namespace analyzer::icmp
