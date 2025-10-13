// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>

#include "zeek/ZValCallback.h"
#include "zeek/analyzer/Analyzer.h"

namespace zeek {
class RecordVal;
}

namespace zeek::analyzer::conn_size {

class ConnSize_Analyzer;

namespace detail {

/**
 * ZValCallback class for num_pkts and num_bytes_ip in the endpoint
 *
 * This is a helper class providing a ZValCallback for the volatile fields on endpoint.
 *
 * type endpoint: record {
 *     size: count;
 *     state: count;
 *     num_pkts: count &optional;  <<
 *     num_bytes_ip: count &optional; <<
 * }
 */
class EndpointRecordValCallback : public zeek::detail::ZValCallback {
public:
    EndpointRecordValCallback() = default;

    /**
     * Destructor removes the field callbacks.
     */
    ~EndpointRecordValCallback() override {
        if ( HasCallbacksAssigned() )
            RemoveCallbacks(*endp_val, is_orig);
    }

    /**
     * Assign callbacks.
     *
     * When should we best call this?
     */
    void AssignCallbacks(ConnSize_Analyzer* conn_size, RecordVal* endp_val, bool is_orig);

    /**
     * Removes the callbacks from the endpoint record
     * and replaces them with the most recent values.
     */
    void RemoveCallbacks(RecordVal& endp_val, bool is_orig);

    bool HasCallbacksAssigned() const noexcept { return conn_size != nullptr && endp_val != nullptr; }

    /**
     * Field lookup callback.
     */
    ZVal operator()(const ZVal& val, const ZVal& field) const override;

    static void InitPostScript();

private:
    ConnSize_Analyzer* conn_size = nullptr;
    RecordVal* endp_val = nullptr;
    bool is_orig = false;

    static int num_pkts_offset;
    static int num_bytes_ip_offset;
};

} // namespace detail

class ConnSize_Analyzer : public analyzer::Analyzer {
public:
    explicit ConnSize_Analyzer(Connection* c);
    ~ConnSize_Analyzer() override = default;

    void Init() override;
    void Done() override;

    uint64_t OrigBytes() const noexcept { return orig_bytes; }
    uint64_t RespBytes() const noexcept { return resp_bytes; }
    uint64_t OrigPackets() const noexcept { return orig_pkts; }
    uint64_t RespPackets() const noexcept { return resp_pkts; }

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

    // Callbacks objects for the endpoint record vals;
    detail::EndpointRecordValCallback orig_cb;
    detail::EndpointRecordValCallback resp_cb;

    static std::vector<uint64_t> generic_pkt_thresholds;
};

// Exposed to make it available to script optimization.
extern zeek::analyzer::Analyzer* GetConnsizeAnalyzer(zeek::Val* cid);

} // namespace zeek::analyzer::conn_size
