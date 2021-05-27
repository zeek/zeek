// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

namespace zeek::packet_analysis::UDP {

class UDPSessionAdapter final : public IP::SessionAdapter {

public:

	UDPSessionAdapter(Connection* conn) :
		IP::SessionAdapter("UDP", conn) { }

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{
		return new UDPSessionAdapter(conn);
		}

	void AddExtraAnalyzers(Connection* conn) override;
	void UpdateConnVal(RecordVal* conn_val) override;

	void UpdateLength(bool is_orig, int len);
	void HandleBadChecksum(bool is_orig);

	// For tracking checksum history. These are connection-specific so they
	// need to be stored in the session adapter created for each connection.
	uint32_t req_chk_cnt = 0;
	uint32_t req_chk_thresh = 1;
	uint32_t rep_chk_cnt = 0;
	uint32_t rep_chk_thresh = 1;

private:

	void UpdateEndpointVal(const ValPtr& endp_arg, bool is_orig);
	void ChecksumEvent(bool is_orig, uint32_t threshold);

	bro_int_t request_len = -1;
	bro_int_t reply_len = -1;
};

} // namespace zeek::packet_analysis::UDP
