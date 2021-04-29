// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Tag.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/plugin/ComponentManager.h"
#include "zeek/iosource/Packet.h"
#include "zeek/packet_analysis/Dispatcher.h"
#include "zeek/PacketFilter.h"

namespace zeek {

namespace detail { class PacketProfiler; }

namespace packet_analysis {

class Analyzer;
using AnalyzerPtr = std::shared_ptr<Analyzer>;

class Manager : public plugin::ComponentManager<Tag, Component> {
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
	 */
	void InitPostScript();

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
	AnalyzerPtr GetAnalyzer(EnumVal *val);

	/**
	 * Looks up an analyzer instance.
	 *
	 * @param name The name of the analyzer.
	 *
	 * @return The analyzer instance or nullptr if no instance is found.
	 */
	AnalyzerPtr GetAnalyzer(const std::string& name);

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

	uint64_t PacketsProcessed() const	{ return num_packets_processed; }

	/**
	 * Records the given packet if a dumper is active.
	 *
	 * @param pkt The packet to record.
	 * @param len The number of bytes to record. If set to zero, the whole
	 * packet is recorded.
	 */
	void DumpPacket(const Packet *pkt, int len=0);

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
	void ReportUnknownProtocol(const std::string& analyzer, uint32_t protocol,
	                           const uint8_t* data=nullptr, size_t len=0);

	/**
	 * Callback method for UnknownProtocolTimer to remove an analyzer/protocol
	 * pair from the map so that it can be logged again.
	 */
	void ResetUnknownProtocolTimer(const std::string& analyzer, uint32_t protocol);

	detail::PacketFilter* GetPacketFilter(bool init=true)
		{
		if ( ! pkt_filter && init )
			pkt_filter = new detail::PacketFilter(detail::packet_filter_default);
		return pkt_filter;
		}

private:
	/**
	 * Instantiates a new analyzer instance.
	 *
	 * @param tag The analyzer's tag.
	 *
	 * @return The new analyzer instance. Returns null if tag is invalid, the
	 * requested analyzer is disabled, or the analyzer can't be instantiated.
	 */
	AnalyzerPtr InstantiateAnalyzer(const Tag& tag);

	/**
	 * Instantiates a new analyzer.
	 *
	 * @param name The name of the analyzer.
	 *
	 * @return The new analyzer instance. Returns null if the name is not known
	 * or if the requested analyzer that is disabled.
	 */
	AnalyzerPtr InstantiateAnalyzer(const std::string& name);

	bool PermitUnknownProtocol(const std::string& analyzer, uint32_t protocol);

	std::map<std::string, AnalyzerPtr> analyzers;
	AnalyzerPtr root_analyzer = nullptr;

	uint64_t num_packets_processed = 0;
	detail::PacketProfiler* pkt_profiler = nullptr;
	detail::PacketFilter* pkt_filter = nullptr;

	using UnknownProtocolPair = std::pair<std::string, uint32_t>;
	std::map<UnknownProtocolPair, uint64_t> unknown_protocols;

	uint64_t unknown_sampling_threshold = 0;
	uint64_t unknown_sampling_rate = 0;
	double unknown_sampling_duration = 0;
	uint64_t unknown_first_bytes_count = 0;
};

} // namespace packet_analysis

extern zeek::packet_analysis::Manager* packet_mgr;

} // namespace zeek
