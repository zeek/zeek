// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>

#include "zeek/RecordFieldCallback.h"
#include "zeek/analyzer/Analyzer.h"

namespace zeek {
class RecordVal;
}

namespace zeek::analyzer::conn_size {

class ConnSize_Analyzer;

namespace detail {

/**
 * RecordFieldCallback class for num_pkts and num_bytes_ip in the endpoint
 * record as previously populated by the ConnSize analyzer.
 *
 * One instance per endpoint is held. This is a bit different from the
 * SessionAdapter approach.
 *
 * XXX: There's a really dark corner here: The ConnSize analyzer has FlipRoles()
 *      implemented, but for TCP it's installed as a packet analyzer child. However,
 *      we never call FlipRoles() on these. This doesn't really seem to matter
 *      it seems, unless a connection is flipped on the second packet after
 *      a SYN-ACK.
 */
class EndpointRecordValCallback : public zeek::detail::RecordFieldCallback {
public:
    EndpointRecordValCallback() = default;
    ~EndpointRecordValCallback() override = default;

    // Avoid copying or assigning instances.
    EndpointRecordValCallback(EndpointRecordValCallback&& o) = delete;
    EndpointRecordValCallback(EndpointRecordValCallback& o) = delete;
    EndpointRecordValCallback& operator=(EndpointRecordValCallback& o) = delete;

    /**
     * Assign callbacks.
     *
     * When should we best call this?
     */
    void Init(ConnSize_Analyzer* conn_size, RecordVal* endp_val, bool is_orig);

    /**
     * Replaces the callbacks within the endpoint record
     * with their most recent values.
     */
    void Done();

    void FlipRoles() { is_orig = ! is_orig; }

    bool HasCallbacksAssigned() const noexcept { return conn_size != nullptr && endp_val != nullptr; }

    /**
     * Implements field lookup for \a num_pkts and \a num_bytes_ip.
     */
    ZVal Invoke(const RecordVal& val, int field) const override;

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

    void Init() override;
    void Done() override;

    // from Analyzer.h
    void InitConnVal(RecordVal& conn_val) override;
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
    friend class detail::EndpointRecordValCallback;

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
