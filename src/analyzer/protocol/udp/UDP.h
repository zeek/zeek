// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "analyzer/Analyzer.h"
#include <netinet/udp.h>

namespace zeek::analyzer::udp {

enum UDP_EndpointState {
	UDP_INACTIVE,	// no packet seen
	UDP_ACTIVE,	// packets seen
};

class UDP_Analyzer final : public zeek::analyzer::TransportLayerAnalyzer {
public:
	explicit UDP_Analyzer(zeek::Connection* conn);
	~UDP_Analyzer() override;

	void Init() override;
	void UpdateConnVal(zeek::RecordVal *conn_val) override;

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new UDP_Analyzer(conn); }

protected:
	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig,
	                   uint64_t seq, const zeek::IP_Hdr* ip, int caplen) override;
	bool IsReuse(double t, const u_char* pkt) override;
	unsigned int MemoryAllocation() const override;

	void ChecksumEvent(bool is_orig, uint32_t threshold);

	// Returns true if the checksum is valid, false if not
	static bool ValidateChecksum(const zeek::IP_Hdr* ip, const struct udphdr* up,
	                             int len);

	bro_int_t request_len, reply_len;

private:
	void UpdateEndpointVal(zeek::RecordVal* endp, bool is_orig);

#define HIST_ORIG_DATA_PKT 0x1
#define HIST_RESP_DATA_PKT 0x2
#define HIST_ORIG_CORRUPT_PKT 0x4
#define HIST_RESP_CORRUPT_PKT 0x8

	// For tracking checksum history.
	uint32_t req_chk_cnt, req_chk_thresh;
	uint32_t rep_chk_cnt, rep_chk_thresh;
};

} // namespace zeek::analyzer::udp

namespace analyzer::udp {

	using UDP_EndpointState [[deprecated("Remove in v4.1. Use zeek::analyzer::udp::UDP_EndpointState.")]] = zeek::analyzer::udp::UDP_EndpointState;
	constexpr auto UDP_INACTIVE [[deprecated("Remove in v4.1. Use zeek::analyzer::udp::UDP_INACTIVE.")]] = zeek::analyzer::udp::UDP_INACTIVE;
	constexpr auto UDP_ACTIVE [[deprecated("Remove in v4.1. Use zeek::analyzer::udp::UDP_ACTIVE.")]] = zeek::analyzer::udp::UDP_ACTIVE;

	using UDP_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::udp::UDP_Analyzer.")]] = zeek::analyzer::udp::UDP_Analyzer;

} // namespace analyzer::udp
