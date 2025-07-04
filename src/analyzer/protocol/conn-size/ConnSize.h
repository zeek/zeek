// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/Analyzer.h"

namespace zeek::analyzer::conn_size {

class ConnSize_Analyzer : public analyzer::Analyzer {
public:
    explicit ConnSize_Analyzer(Connection* c);
    ~ConnSize_Analyzer() override = default;

    void Init() override;
    void Done() override;

    // from Analyzer.h
    void UpdateConnVal(RecordVal* conn_val) override;
    void FlipRoles() override;

    void SetByteAndPacketThreshold(uint64_t threshold, bool bytes, bool orig);
    uint64_t GetByteAndPacketThreshold(bool bytes, bool orig);

    void SetDurationThreshold(double duration);
    double GetDurationThreshold() { return duration_thresh; };

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new ConnSize_Analyzer(conn); }

    /**
     * Update the generic packet thresholds.
     *
     * @param thresholds The generic packet thresholds to set.
     */
    static void SetGenericPacketThresholds(std::vector<uint64_t> thresholds) {
        generic_pkt_thresholds = std::move(thresholds);
    };

protected:
    void DeliverPacket(int len, const u_char* data, bool is_orig, uint64_t seq, const IP_Hdr* ip, int caplen) override;
    void CheckThresholds(bool is_orig);
    void NextGenericPacketThreshold();

    void ThresholdEvent(EventHandlerPtr f, uint64_t threshold, bool is_orig);

    uint64_t orig_bytes = 0;
    uint64_t resp_bytes = 0;
    uint64_t orig_pkts = 0;
    uint64_t resp_pkts = 0;

    uint64_t orig_bytes_thresh = 0;
    uint64_t resp_bytes_thresh = 0;
    uint64_t orig_pkts_thresh = 0;
    uint64_t resp_pkts_thresh = 0;

    uint64_t generic_pkt_thresh = 0;
    size_t generic_pkt_thresh_next_idx = 0;

    double start_time = 0.0;
    double duration_thresh = 0.0;

    static std::vector<uint64_t> generic_pkt_thresholds;
};

// Exposed to make it available to script optimization.
extern zeek::analyzer::Analyzer* GetConnsizeAnalyzer(zeek::Val* cid);

} // namespace zeek::analyzer::conn_size
