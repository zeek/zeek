// See the file "COPYING" in the main distribution directory for copyright.
//

#ifndef ANALYZER_PROTOCOL_CONN_SIZE_CONNSIZE_H
#define ANALYZER_PROTOCOL_CONN_SIZE_CONNSIZE_H

#include "analyzer/Analyzer.h"
#include "NetVar.h"

#include <set>
#include <string>

namespace analyzer { namespace conn_size {

class ConnSize_Analyzer : public analyzer::Analyzer {
public:
	explicit ConnSize_Analyzer(Connection* c);
	~ConnSize_Analyzer() override;

	void Init() override;
	void Done() override;

	// from Analyzer.h
	void UpdateConnVal(RecordVal *conn_val) override;
	void FlipRoles() override;

	void SetThreshold(uint64_t threshold, bool bytes, bool orig);
	uint64 GetThreshold(bool bytes, bool orig);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new ConnSize_Analyzer(conn); }

	// wzj
	void RuleMatches(Rule *r, bool is_orig);
	void RuleNotMatch(Rule *r, bool is_orig);

protected:
	void DeliverPacket(int len, const u_char* data, bool is_orig,
					uint64 seq, const IP_Hdr* ip, int caplen) override;
	void CheckSizes(bool is_orig);

	void ThresholdEvent(EventHandlerPtr f, uint64 threshold, bool is_orig);

	uint64_t orig_bytes;
	uint64_t resp_bytes;
	uint64_t orig_pkts;
	uint64_t resp_pkts;

	uint64_t orig_bytes_thresh;
	uint64_t resp_bytes_thresh;
	uint64_t orig_pkts_thresh;
	uint64_t resp_pkts_thresh;

	// wzj
	uint64_t orig_data_bytes;	// data bytes sent from orig
	uint64_t resp_data_bytes;	// data bytes sent form resp
	uint64_t orig_data_pkts;	// data packets sent from orig
	uint64_t resp_data_pkts;	// data packets sent form resp
	uint64_t data_bytes;            // data bytes sent from both directions
	uint64_t data_pkts;             // data packets sent form both directions

	std::set<std::string> rules_matched_first_packet;
	std::set<std::string> rules_matched_later_packets;
	std::set<std::string> rules_not_matched_later_packets;
};

} } // namespace analyzer::* 

#endif
