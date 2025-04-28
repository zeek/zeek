// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/PacketFilter.h"
#include "zeek/Tag.h"
#include "zeek/iosource/Packet.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/Dispatcher.h"
#include "zeek/plugin/ComponentManager.h"

namespace zeek {

namespace detail {
class PacketProfiler;
}

namespace iosource {
class PktDumper;
}

namespace packet_analysis {

class Analyzer;
using AnalyzerPtr = std::shared_ptr<Analyzer>;

class Manager : public plugin::ComponentManager<Component> {
public:
    /**
     * Constructor.
     */
    Manager();

    /**
     * Destructor.
     */
    ~Manager();

    /**
     * Second-stage initialization of the manager. This is called late
     * during Zeek's initialization after any scripts are processed.
     *
     * @param unprocessed_output_file A path to a file where unprocessed
     * packets will be written. This can be an empty string to disable
     * writing packets.
     */
    void InitPostScript(const std::string& unprocessed_output_file);

    /**
     * Finished the manager's operations.
     */
    void Done();

    /**
     * Dumps out the state of all registered analyzers to the \c analyzer
     * debug stream. Should be called only after any \c zeek_init events
     * have executed to ensure that any of their changes are applied.
     */
    void DumpDebug(); // Called after zeek_init() events.

    /**
     * Looks up an analyzer instance.
     *
     * @param val The analyzer's tag value.
     *
     * @return The analyzer instance or nullptr if no instance is found.
     */
    AnalyzerPtr GetAnalyzer(EnumVal* val);

    /**
     * Looks up an analyzer instance.
     *
     * @param name The name of the analyzer.
     *
     * @return The analyzer instance or nullptr if no instance is found.
     */
    AnalyzerPtr GetAnalyzer(const std::string& name);

    /**
     * Enables an analyzer type. Only enabled analyzers will participate
     * in packet processing.
     *
     * @param tag The analyzer's tag.
     *
     * @return True if successful.
     */
    bool EnableAnalyzer(zeek::EnumVal* tag);

    /**
     * Enables an analyzer type. Only enabled analyzers will participate
     * in packet processing.
     *
     * @param tag The analyzer's tag.
     *
     * @return True if successful.
     */
    bool EnableAnalyzer(const zeek::Tag& tag) { return EnableAnalyzer(tag.AsVal().get()); }

    /**
     * Disables an analyzer type. Disabled analyzers will not participate
     * in packet processing.
     *
     * @param tag The packet analyzer's tag.
     *
     * @return True if successful.
     */
    bool DisableAnalyzer(zeek::EnumVal* tag);

    /**
     * Disables an analyzer type. Disabled analyzers will not participate
     * in packet processing.
     *
     * @param tag The packet analyzer's tag.
     *
     * @return True if successful.
     */
    bool DisableAnalyzer(const zeek::Tag& tag) { return DisableAnalyzer(tag.AsVal().get()); };

    /**
     * Processes a packet by applying the configured packet analyzers.
     *
     * @param packet The packet to process.
     */
    void ProcessPacket(Packet* packet);

    /**
     * Process the inner packet of an encapsulation. This can be used by tunnel
     * analyzers to process a inner packet from the "beginning" directly through
     * the root analyzer. This short-circuits some of the additional processing
     * that happens in ProcessPacket().
     *
     * @param packet The packet to process.
     */
    bool ProcessInnerPacket(Packet* packet);

    uint64_t PacketsProcessed() const { return num_packets_processed; }

    /**
     * Records the given packet if a dumper is active.
     *
     * @param pkt The packet to record.
     * @param len The number of bytes to record. If set to zero, the whole
     * packet is recorded.
     */
    void DumpPacket(const Packet* pkt, int len = 0);

    /**
     * Attempts to write an entry to unknown_protocols.log, rate-limited to avoid
     * spamming the log with duplicates.
     *
     * @param analyzer The name of the analyzer that was trying to forward the packet.
     * @param protocol The protocol of the next header that couldn't be forwarded.
     * @param data A pointer to the data of the next header being processed. If this
     * is passed as a nullptr, the first_bytes log column will be blank.
     * @param len The remaining length of the data in the packet being processed.
     */
    void ReportUnknownProtocol(const std::string& analyzer, uint32_t protocol, const uint8_t* data = nullptr,
                               size_t len = 0);

    /**
     * Callback method for UnknownProtocolTimer to remove an analyzer/protocol
     * pair from the map so that it can be logged again.
     */
    void ResetUnknownProtocolTimer(const std::string& analyzer, uint32_t protocol);

    zeek::detail::PacketFilter* GetPacketFilter(bool init = true) {
        if ( ! pkt_filter && init )
            pkt_filter = new zeek::detail::PacketFilter(zeek::detail::packet_filter_default);
        return pkt_filter;
    }

    /**
     * Returns the total number of packets received that weren't considered
     * processed by some analyzer.
     */
    uint64_t GetUnprocessedCount() const { return total_not_processed; }

    /**
     * Tracks the given analyzer for the current packet's analyzer history.
     * The packet analyzer history is implemented in form of a stack, which is reset on a
     * call to ProcessPacket() but maintained throughout calls to ProcessInnerPacket().
     *
     * @param analyzer The analyzer to track.
     * @param len The remaining length of the data in the packet being processed.
     * @param data A pointer to the data
     */
    void TrackAnalyzer(const Analyzer* analyzer, size_t len, const uint8_t* data) {
        analyzer_stack.push_back({analyzer, {data, len}});
    }

    /**
     * Get all tracked data spans for a given analyzer instance.
     *
     * @analyzer The analyzer instance.
     *
     * @returns An array of data spans.
     */
    std::vector<zeek::Span<const uint8_t>> GetAnalyzerData(const AnalyzerPtr& analyzer);

private:
    /**
     * Instantiates a new analyzer instance.
     *
     * @param tag The analyzer's tag.
     *
     * @return The new analyzer instance. Returns null if tag is invalid, the
     * requested analyzer is disabled, or the analyzer can't be instantiated.
     */
    AnalyzerPtr InstantiateAnalyzer(const zeek::Tag& tag);

    /**
     * Instantiates a new analyzer.
     *
     * @param name The name of the analyzer.
     *
     * @return The new analyzer instance. Returns null if the name is not known
     * or if the requested analyzer that is disabled.
     */
    AnalyzerPtr InstantiateAnalyzer(const std::string& name);

    /**
     * Generates a string vector that represents the analyzer history of the
     * current packet based on the analyzers' tags.
     *
     * @return A vector of strings representing the packet analyzer history.
     */
    VectorValPtr BuildAnalyzerHistory() const;

    bool PermitUnknownProtocol(const std::string& analyzer, uint32_t protocol);

    std::map<std::string, AnalyzerPtr> analyzers;
    AnalyzerPtr root_analyzer = nullptr;

    uint64_t num_packets_processed = 0;
    zeek::detail::PacketProfiler* pkt_profiler = nullptr;
    zeek::detail::PacketFilter* pkt_filter = nullptr;

    using UnknownProtocolPair = std::pair<std::string, uint32_t>;
    std::map<UnknownProtocolPair, uint64_t> unknown_protocols;

    uint64_t unknown_sampling_threshold = 0;
    uint64_t unknown_sampling_rate = 0;
    double unknown_sampling_duration = 0;
    uint64_t unknown_first_bytes_count = 0;

    uint64_t total_not_processed = 0;
    iosource::PktDumper* unprocessed_dumper = nullptr;

    struct StackEntry {
        const Analyzer* analyzer;
        zeek::Span<const uint8_t> data; // Start of this layer, limited by span's size.
    };

    std::vector<StackEntry> analyzer_stack;
};

} // namespace packet_analysis

extern zeek::packet_analysis::Manager* packet_mgr;

} // namespace zeek
