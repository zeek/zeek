// See the file "COPYING" in the main distribution directory for copyright.
//

#pragma once

#include "analyzer/Analyzer.h"
#include "NetVar.h"

namespace analyzer { namespace conn_size {

class ConnSize_Analyzer : public zeek::analyzer::Analyzer {
public:
	explicit ConnSize_Analyzer(Connection* c);
	~ConnSize_Analyzer() override;

	void Init() override;
	void Done() override;

	// from Analyzer.h
	void UpdateConnVal(zeek::RecordVal *conn_val) override;
	void FlipRoles() override;

	void SetByteAndPacketThreshold(uint64_t threshold, bool bytes, bool orig);
	uint64_t GetByteAndPacketThreshold(bool bytes, bool orig);

	void SetDurationThreshold(double duration);
	double GetDurationThreshold() { return duration_thresh; };

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new ConnSize_Analyzer(conn); }

protected:
	void DeliverPacket(int len, const u_char* data, bool is_orig,
					   uint64_t seq, const IP_Hdr* ip, int caplen) override;
	void CheckThresholds(bool is_orig);

	void ThresholdEvent(EventHandlerPtr f, uint64_t threshold, bool is_orig);

	uint64_t orig_bytes;
	uint64_t resp_bytes;
	uint64_t orig_pkts;
	uint64_t resp_pkts;

	uint64_t orig_bytes_thresh;
	uint64_t resp_bytes_thresh;
	uint64_t orig_pkts_thresh;
	uint64_t resp_pkts_thresh;

	double start_time;
	double duration_thresh;
};

} } // namespace analyzer::*
