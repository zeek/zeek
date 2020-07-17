// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <queue>
#include <vector>

#include "Config.h"
#include "Tag.h"
#include "Component.h"
#include "plugin/ComponentManager.h"
#include "iosource/Packet.h"
#include "Dict.h"
#include "net_util.h"

namespace zeek::packet_analysis {

class Analyzer;
class Dispatcher;
using AnalyzerPtr = std::shared_ptr<Analyzer>;
using DispatcherPtr = std::shared_ptr<Dispatcher>;

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
	 * Returns the tag associated with an analyer name, or the tag
	 * associated with an error if no such analyzer exists.
	 *
	 * @param name The canonical analyzer name to check.
	 */
	Tag GetAnalyzerTag(const char* name);

	/**
	 * Instantiates a new analyzer instance.
	 *
	 * @param tag The analyzer's tag.
	 *
	 * @return The new analyzer instance. Returns
	 * null if tag is invalid, the requested analyzer is disabled, or the
	 * analyzer can't be instantiated.
	 */
	AnalyzerPtr InstantiateAnalyzer(const Tag& tag);

	/**
	 * Instantiates a new analyzer.
	 *
	 * @param name The name of the analyzer.
	 *
	 * @return The new analyzer instance. Returns
	 * null if the name is not known or if the requested analyzer that is
	 * disabled.
	 */
	AnalyzerPtr InstantiateAnalyzer(const std::string& name);

	/**
	 * Processes a packet by applying the configured packet analyzers.
	 *
	 * @param packet The packet to process.
	 */
	void ProcessPacket(Packet* packet);

private:

	/**
	 * Skips a fixed amount of packet data that is defined by encap_hdr_size.
	 * It is assumed that an IP header follows.
	 *
	 * @param packet The packet to adapt.
	 *
	 * @param data Pointer to remaining payload.
	 */
	void CustomEncapsulationSkip(Packet* packet, const uint8_t* data);

	AnalyzerPtr Dispatch(uint32_t identifier);

	DispatcherPtr GetDispatcher(Config& configuration, const std::string& dispatcher_name);

	std::map<std::string, AnalyzerPtr> analyzers;
	std::map<std::string, DispatcherPtr> dispatchers;
	DispatcherPtr root_dispatcher = nullptr;
	DispatcherPtr default_dispatcher = nullptr;
	DispatcherPtr current_state = nullptr;
	AnalyzerPtr default_analyzer = nullptr;
};

}

extern zeek::packet_analysis::Manager* packet_mgr;
