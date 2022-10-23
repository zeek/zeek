// See the file "COPYING" in the main distribution directory for copyright.

/**
 * The central management unit for registering and instantiating analyzers.
 *
 * For each protocol that Zeek supports, there's one class derived from
 * analyzer::Analyzer. Once we have decided that a connection's payload is to
 * be parsed as a given protocol, we instantiate the corresponding
 * analyzer-derived class and add the new instance as a child node into the
 * connection's analyzer tree.
 *
 * In addition to the analyzer-derived class itself, for each protocol
 * there's also "meta-class" derived from analyzer::Component that describes
 * the analyzer, including status information on if that particular protocol
 * analysis is currently enabled.
 *
 * To identify an analyzer (or to be precise: a component), the manager
 * maintains mappings of (1) analyzer::Tag to component, and (2)
 * human-readable analyzer name to component.
 */
#pragma once

#include <queue>
#include <vector>

#include "zeek/IP.h"
#include "zeek/Tag.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/analyzer.bif.h"
#include "zeek/net_util.h"
#include "zeek/plugin/ComponentManager.h"

namespace zeek
	{

namespace packet_analysis::IP
	{

class IPBasedAnalyzer;
class SessionAdapter;

	} // namespace packet_analysis::IP

namespace analyzer
	{

/**
 * Class maintaining and scheduling available protocol analyzers.
 *
 * The manager maintains a registry of all available protocol analyzers,
 * including a mapping between their textual names and Tag. It
 * instantantiates new analyzers on demand. For new connections, the manager
 * sets up their initial analyzer tree, including adding the right \c PIA,
 * respecting well-known ports, and tracking any analyzers specifically
 * scheduled for individidual connections.
 */
class Manager : public plugin::ComponentManager<Component>
	{
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
	 * Enables an analyzer type. Only enabled analyzers will be
	 * instantiated for new connections.
	 *
	 * @param tag The analyzer's tag.
	 *
	 * @return True if successful.
	 */
	bool EnableAnalyzer(const zeek::Tag& tag);

	/**
	 * Enables an analyzer type. Only enabled analyzers will be
	 * instantiated for new connections.
	 *
	 * @param tag The analyzer's tag as an enum of script type \c
	 * Tag.
	 *
	 * @return True if successful.
	 */
	bool EnableAnalyzer(EnumVal* tag);

	/**
	 * Enables an analyzer type. Disabled analyzers will not be
	 * instantiated for new connections.
	 *
	 * @param tag The analyzer's tag.
	 *
	 * @return True if successful.
	 */
	bool DisableAnalyzer(const zeek::Tag& tag);

	/**
	 * Disables an analyzer type. Disabled analyzers will not be
	 * instantiated for new connections.
	 *
	 * @param tag The analyzer's tag as an enum of script type \c
	 * Tag.
	 *
	 * @return True if successful.
	 */
	bool DisableAnalyzer(EnumVal* tag);

	/**
	 * Disables all currently registered analyzers.
	 */
	void DisableAllAnalyzers();

	/**
	 * Returns the tag associated with an analyzer name, or the tag
	 * associated with an error if no such analyzer exists.
	 *
	 * @param name The canonical analyzer name to check.
	 */
	zeek::Tag GetAnalyzerTag(const char* name);

	/**
	 * Returns true if an analyzer is enabled.
	 *
	 * @param tag The analyzer's tag.
	 */
	bool IsEnabled(const zeek::Tag& tag);

	/**
	 * Returns true if an analyzer is enabled.
	 *
	 * @param tag The analyzer's tag as an enum of script type \c
	 * Tag.
	 */
	bool IsEnabled(EnumVal* tag);

	/**
	 * Registers a well-known port for an analyzer. Once registered,
	 * connection on that port will start with a corresponding analyzer
	 * assigned.
	 *
	 * @param tag The analyzer's tag as an enum of script type \c
	 * Tag.
	 *
	 * @param port The well-known port.
	 *
	 * @return True if successful.
	 */
	bool RegisterAnalyzerForPort(EnumVal* tag, PortVal* port);

	/**
	 * Registers a well-known port for an analyzer. Once registered,
	 * connection on that port will start with a corresponding analyzer
	 * assigned.
	 *
	 * @param tag The analyzer's tag.
	 *
	 * @param proto The port's protocol.
	 *
	 * @param port The port's number.
	 *
	 * @return True if successful.
	 */
	bool RegisterAnalyzerForPort(const zeek::Tag& tag, TransportProto proto, uint32_t port);

	/**
	 * Unregisters a well-known port for an analyzers.
	 *
	 * @param tag The analyzer's tag as an enum of script type \c
	 * Tag.
	 *
	 * @param port The well-known port.
	 *
	 * @return True if successful (incl. when the port wasn't actually
	 * registered for the analyzer).
	 *
	 */
	bool UnregisterAnalyzerForPort(EnumVal* tag, PortVal* port);

	/**
	 * Unregisters a well-known port for an analyzers.
	 *
	 * @param tag The analyzer's tag.
	 *
	 * @param proto The port's protocol.
	 *
	 * @param port The port's number.
	 *
	 * @param tag The analyzer's tag as an enum of script type \c
	 * Tag.
	 */
	bool UnregisterAnalyzerForPort(const zeek::Tag& tag, TransportProto proto, uint32_t port);

	/**
	 * Instantiates a new analyzer instance for a connection.
	 *
	 * @param tag The analyzer's tag.
	 *
	 * @param conn The connection the analyzer is to be associated with.
	 *
	 * @return The new analyzer instance. Note that the analyzer will not
	 * have been added to the connection's analyzer tree yet. Returns
	 * null if tag is invalid, the requested analyzer is disabled, or the
	 * analyzer can't be instantiated.
	 */
	Analyzer* InstantiateAnalyzer(const zeek::Tag& tag, Connection* c);

	/**
	 * Instantiates a new analyzer instance for a connection.
	 *
	 * @param name The name of the analyzer.
	 *
	 * @param conn The connection the analyzer is to be associated with.
	 *
	 * @return The new analyzer instance. Note that the analyzer will not
	 * have been added to the connection's analyzer tree yet. Returns
	 * null if the name is not known or if the requested analyzer that is
	 * disabled.
	 */
	Analyzer* InstantiateAnalyzer(const char* name, Connection* c);

	/**
	 * Schedules a particular analyzer for an upcoming connection. Once
	 * the connection is seen, BuildInitAnalyzerTree() will add the
	 * specified analyzer to its tree.
	 *
	 * @param orig The connection's anticipated originator address.
	 * 0.0.0.0 can be used as a wildcard matching any originator.
	 *
	 * @param resp The connection's anticipated responder address (no
	 * wilcard).
	 *
	 * @param resp_p The connection's anticipated responder port.
	 *
	 * @param proto The connection's anticipated transport protocol.
	 *
	 * @param analyzer The analyzer to use once the connection is seen.
	 *
	 * @param timeout An interval after which to timeout the request to
	 * schedule this analyzer. Must be non-zero.
	 */
	void ScheduleAnalyzer(const IPAddr& orig, const IPAddr& resp, uint16_t resp_p,
	                      TransportProto proto, const zeek::Tag& analyzer, double timeout);

	/**
	 * Schedules a particular analyzer for an upcoming connection. Once
	 * the connection is seen, BuildInitAnalyzerTree() will add the
	 * specified analyzer to its tree.
	 *
	 * @param orig The connection's anticipated originator address. 0 can
	 * be used as a wildcard matching any originator.
	 *
	 * @param resp The The connection's anticipated responder address (no
	 * wilcard).
	 *
	 * @param resp_p The connection's anticipated responder port.
	 *
	 * @param proto The connection's anticipated transport protocol.
	 *
	 * @param analyzer The name of the analyzer to use once the
	 * connection is seen.
	 *
	 * @param timeout An interval after which to timeout the request to
	 * schedule this analyzer. Must be non-zero.
	 */
	void ScheduleAnalyzer(const IPAddr& orig, const IPAddr& resp, uint16_t resp_p,
	                      TransportProto proto, const char* analyzer, double timeout);

	/**
	 * Searched for analyzers scheduled to be attached to a given connection
	 * and then attaches them.
	 *
	 * @param conn The connection to which scheduled analyzers are attached.
	 *
	 * @param init True if the newly added analyzers should be
	 * immediately initialized.
	 *
	 * @param root If given, the scheduled analyzers will become childs
	 * of this; if not given the connection's root analyzer is used
	 * instead.
	 *
	 * @return True if at least one scheduled analyzer was found.
	 */
	bool ApplyScheduledAnalyzers(Connection* conn, bool init_and_event = true,
	                             packet_analysis::IP::SessionAdapter* parent = nullptr);

	/**
	 * Schedules a particular analyzer for an upcoming connection. Once
	 * the connection is seen, BuildInitAnalyzerTree() will add the
	 * specified analyzer to its tree.
	 *
	 * @param orig The connection's anticipated originator address. 0 can
	 * be used as a wildcard matching any originator.
	 *
	 * @param resp The connection's anticipated responder address (no
	 * wilcard).
	 *
	 * @param resp_p The connection's anticipated responder port.
	 *
	 * @param analyzer The analyzer to use once the connection is seen as
	 * an enum value of script-type \c Tag.
	 *
	 * @param timeout An interval after which to timeout the request to
	 * schedule this analyzer. Must be non-zero.
	 */
	void ScheduleAnalyzer(const IPAddr& orig, const IPAddr& resp, PortVal* resp_p, Val* analyzer,
	                      double timeout);

	/**
	 * @return the UDP port numbers to be associated with VXLAN traffic.
	 */
	const std::vector<uint16_t>& GetVxlanPorts() const { return vxlan_ports; }

private:
	// Internal version that must be used only once InitPostScript has completed.
	bool RegisterAnalyzerForPort(const std::tuple<zeek::Tag, TransportProto, uint32_t>& p);

	friend class packet_analysis::IP::IPBasedAnalyzer;

	using tag_set = std::set<zeek::Tag>;

	tag_set GetScheduled(const Connection* conn);
	void ExpireScheduledAnalyzers();

	//// Data structures to track analyzed scheduled for future connections.

	// The index for a scheduled connection.
	struct ConnIndex
		{
		IPAddr orig;
		IPAddr resp;
		uint16_t resp_p;
		uint16_t proto;

		ConnIndex(const IPAddr& _orig, const IPAddr& _resp, uint16_t _resp_p, uint16_t _proto);
		ConnIndex();

		bool operator<(const ConnIndex& other) const;
		};

	// Information associated with a scheduled connection.
	struct ScheduledAnalyzer
		{
		ConnIndex conn;
		zeek::Tag analyzer;
		double timeout;

		struct Comparator
			{
			bool operator()(ScheduledAnalyzer* a, ScheduledAnalyzer* b)
				{
				return a->timeout > b->timeout;
				}
			};
		};

	using protocol_analyzers = std::set<std::tuple<zeek::Tag, TransportProto, uint32_t>>;
	using conns_map = std::multimap<ConnIndex, ScheduledAnalyzer*>;
	using conns_queue = std::priority_queue<ScheduledAnalyzer*, std::vector<ScheduledAnalyzer*>,
	                                        ScheduledAnalyzer::Comparator>;

	bool initialized = false;
	protocol_analyzers pending_analyzers_for_ports;

	conns_map conns;
	conns_queue conns_by_timeout;
	std::vector<uint16_t> vxlan_ports;
	};

	} // namespace analyzer

extern analyzer::Manager* analyzer_mgr;

	} // namespace zeek

// Macros for analyzer debug logging which include the connection id into the
// message.
#ifdef DEBUG
#define DBG_ANALYZER(conn, txt)                                                                    \
	DBG_LOG(zeek::DBG_ANALYZER, "%s " txt,                                                         \
	        fmt_conn_id(conn->OrigAddr(), ntohs(conn->OrigPort()), conn->RespAddr(),               \
	                    ntohs(conn->RespPort())));
#define DBG_ANALYZER_ARGS(conn, fmt, args...)                                                      \
	DBG_LOG(zeek::DBG_ANALYZER, "%s " fmt,                                                         \
	        fmt_conn_id(conn->OrigAddr(), ntohs(conn->OrigPort()), conn->RespAddr(),               \
	                    ntohs(conn->RespPort())),                                                  \
	        ##args);
#else
#define DBG_ANALYZER(conn, txt)
#define DBG_ANALYZER_ARGS(conn, fmt, args...)
#endif
