// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h>

#include <string>
#include <tuple>
#include <type_traits>

#include "Dict.h"
#include "Timer.h"
#include "Rule.h"
#include "IPAddr.h"
#include "UID.h"
#include "WeirdState.h"
#include "ZeekArgs.h"
#include "IntrusivePtr.h"
#include "iosource/Packet.h"

#include "analyzer/Tag.h"
#include "analyzer/Analyzer.h"

class Connection;
class ConnectionTimer;
class NetSessions;
class LoginConn;
class RuleHdrTest;
class Specific_RE_Matcher;
class RuleEndpointState;
class EncapsulationStack;

ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(RecordVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(TransportLayerAnalyzer, zeek, analyzer);
ZEEK_FORWARD_DECLARE_NAMESPACED(Analyzer, zeek, analyzer);

namespace zeek {
using ValPtr = zeek::IntrusivePtr<Val>;
using RecordValPtr = zeek::IntrusivePtr<RecordVal>;
}

typedef enum {
	NUL_IN_LINE,
	SINGULAR_CR,
	SINGULAR_LF,
	NUM_EVENTS_TO_FLAG,
} ConnEventToFlag;

typedef void (Connection::*timer_func)(double t);

struct ConnID {
	IPAddr src_addr;
	IPAddr dst_addr;
	uint32_t src_port;
	uint32_t dst_port;
	bool is_one_way;	// if true, don't canonicalize order
};

static inline int addr_port_canon_lt(const IPAddr& addr1, uint32_t p1,
					const IPAddr& addr2, uint32_t p2)
	{
	return addr1 < addr2 || (addr1 == addr2 && p1 < p2);
	}

class Connection final : public zeek::Obj {
public:
	Connection(NetSessions* s, const ConnIDKey& k, double t, const ConnID* id,
	           uint32_t flow, const Packet* pkt, const EncapsulationStack* arg_encap);
	~Connection() override;

	// Invoked when an encapsulation is discovered. It records the
	// encapsulation with the connection and raises a "tunnel_changed"
	// event if it's different from the previous encapsulation (or the
	// first encountered). encap can be null to indicate no
	// encapsulation.
	void CheckEncapsulation(const EncapsulationStack* encap);

	// Invoked when connection is about to be removed.  Use Ref(this)
	// inside Done to keep the connection object around (though it'll
	// no longer be accessible from the dictionary of active
	// connections).
	void Done();

	// Process the connection's next packet.  "data" points just
	// beyond the IP header.  It's updated to point just beyond
	// the transport header (or whatever should be saved, if we
	// decide not to save the full packet contents).
	//
	// If record_packet is true, the packet should be recorded.
	// If record_content is true, then its entire contents should
	// be recorded, otherwise just up through the transport header.
	// Both are assumed set to true when called.
	void NextPacket(double t, bool is_orig,
			const IP_Hdr* ip, int len, int caplen,
			const u_char*& data,
			int& record_packet, int& record_content,
			// arguments for reproducing packets
			const Packet *pkt);

	// Keys are only considered valid for a connection when a
	// connection is in the session map. If it is removed, the key
	// should be marked invalid.
	const ConnIDKey& Key() const	{ return key; }
	void ClearKey()					{ key_valid = false; }
	bool IsKeyValid() const			{ return key_valid; }

	double StartTime() const		{ return start_time; }
	void SetStartTime(double t)		{ start_time = t; }
	double LastTime() const			{ return last_time; }
	void SetLastTime(double t) 		{ last_time = t; }

	const IPAddr& OrigAddr() const		{ return orig_addr; }
	const IPAddr& RespAddr() const		{ return resp_addr; }

	uint32_t OrigPort() const			{ return orig_port; }
	uint32_t RespPort() const			{ return resp_port; }

	void FlipRoles();

	zeek::analyzer::Analyzer* FindAnalyzer(zeek::analyzer::ID id);
	zeek::analyzer::Analyzer* FindAnalyzer(const zeek::analyzer::Tag& tag);	// find first in tree.
	zeek::analyzer::Analyzer* FindAnalyzer(const char* name);	// find first in tree.

	TransportProto ConnTransport() const { return proto; }

	bool IsSuccessful() const	{ return is_successful; };
	void SetSuccessful()	{ is_successful = true; }

	// True if we should record subsequent packets (either headers or
	// in their entirety, depending on record_contents).  We still
	// record subsequent SYN/FIN/RST, regardless of how this is set.
	bool RecordPackets() const		{ return record_packets; }
	void SetRecordPackets(bool do_record)	{ record_packets = do_record ? 1 : 0; }

	// True if we should record full packets for this connection,
	// false if we should just record headers.
	bool RecordContents() const		{ return record_contents; }
	void SetRecordContents(bool do_record)	{ record_contents = do_record ? 1 : 0; }

	// Set whether to record *current* packet header/full.
	void SetRecordCurrentPacket(bool do_record)
		{ record_current_packet = do_record ? 1 : 0; }
	void SetRecordCurrentContent(bool do_record)
		{ record_current_content = do_record ? 1 : 0; }

	// FIXME: Now this is in Analyzer and should eventually be removed here.
	//
	// If true, skip processing of remainder of connection.  Note
	// that this does not in itself imply that record_packets is false;
	// we might want instead to process the connection off-line.
	void SetSkip(bool do_skip)		{ skip = do_skip ? 1 : 0; }
	bool Skipping() const			{ return skip; }

	// Arrange for the connection to expire after the given amount of time.
	void SetLifetime(double lifetime);

	// Returns true if the packet reflects a reuse of this
	// connection (i.e., not a continuation but the beginning of
	// a new connection).
	bool IsReuse(double t, const u_char* pkt);

	// Get/set the inactivity timeout for this connection.
	void SetInactivityTimeout(double timeout);
	double InactivityTimeout() const	{ return inactivity_timeout; }

	// Activate connection_status_update timer.
	void EnableStatusUpdateTimer();

	[[deprecated("Remove in v4.1.  Use ConnVal() instead.")]]
	zeek::RecordVal* BuildConnVal();

	/**
	 * Returns the associated "connection" record.
	 */
	const zeek::RecordValPtr& ConnVal();

	void AppendAddl(const char* str);

	LoginConn* AsLoginConn()		{ return login_conn; }

	void Match(Rule::PatternType type, const u_char* data, int len,
			bool is_orig, bool bol, bool eol, bool clear_state);

	/**
	 * Generates connection removal event(s).
	 */
	void RemovalEvent();

	// If a handler exists for 'f', an event will be generated.  If 'name' is
	// given that event's first argument will be it, and it's second will be
	// the connection value.  If 'name' is null, then the event's first
	// argument is the connection value.
	void Event(EventHandlerPtr f, zeek::analyzer::Analyzer* analyzer, const char* name = nullptr);

	// If a handler exists for 'f', an event will be generated.  In any case,
	// 'v1' and 'v2' reference counts get decremented.  The event's first
	// argument is the connection value, second argument is 'v1', and if 'v2'
	// is given that will be it's third argument.
	[[deprecated("Remove in v4.1.  Use EnqueueEvent() instead (note it doesn't automatically add the connection argument).")]]
	void Event(EventHandlerPtr f, zeek::analyzer::Analyzer* analyzer, zeek::Val* v1, zeek::Val* v2 = nullptr);

	// If a handler exists for 'f', an event will be generated.  In any case,
	// reference count for each element in the 'vl' list are decremented.  The
	// arguments used for the event are whatevever is provided in 'vl'.
	[[deprecated("Remove in v4.1.  Use EnqueueEvent() instead.")]]
	void ConnectionEvent(EventHandlerPtr f, zeek::analyzer::Analyzer* analyzer,
				val_list vl);

	// Same as ConnectionEvent, except taking the event's argument list via a
	// pointer instead of by value.  This function takes ownership of the
	// memory pointed to by 'vl' and also for decrementing the reference count
	// of each of its elements.
	[[deprecated("Remove in v4.1.  Use EnqueueEvent() instead.")]]
	void ConnectionEvent(EventHandlerPtr f, zeek::analyzer::Analyzer* analyzer,
				val_list* vl);

	// Queues an event without first checking if there's any available event
	// handlers (or remote consumes).  If it turns out there's actually nothing
	// that will consume the event, then this may leak memory due to failing to
	// decrement the reference count of each element in 'vl'.  i.e. use this
	// function instead of ConnectionEvent() if you've already guarded against
	// the case where there's no handlers (one usually also does that because
	// it would be a waste of effort to construct all the event arguments when
	// there's no handlers to consume them).
	[[deprecated("Remove in v4.1.  Use EnqueueEvent() instead.")]]
	void ConnectionEventFast(EventHandlerPtr f, zeek::analyzer::Analyzer* analyzer,
				val_list vl);

	/**
	 * Enqueues an event associated with this connection and given analyzer.
	 */
	void EnqueueEvent(EventHandlerPtr f, zeek::analyzer::Analyzer* analyzer,
	                  zeek::Args args);

	/**
	 * A version of EnqueueEvent() taking a variable number of arguments.
	 */
	template <class... Args>
	std::enable_if_t<
		std::is_convertible_v<
			std::tuple_element_t<0, std::tuple<Args...>>, zeek::ValPtr>>
	EnqueueEvent(EventHandlerPtr h, zeek::analyzer::Analyzer* analyzer, Args&&... args)
		{ return EnqueueEvent(h, analyzer, zeek::Args{std::forward<Args>(args)...}); }

	void Weird(const char* name, const char* addl = "");
	bool DidWeird() const	{ return weird != 0; }

	// Cancel all associated timers.
	void CancelTimers();

	inline bool FlagEvent(ConnEventToFlag e)
		{
		if ( e >= 0 && e < NUM_EVENTS_TO_FLAG )
			{
			if ( suppress_event & (1 << e) )
				return false;
			suppress_event |= 1 << e;
			}

		return true;
		}

	void Describe(ODesc* d) const override;
	void IDString(ODesc* d) const;

	// Statistics.

	// Just a lower bound.
	unsigned int MemoryAllocation() const;
	unsigned int MemoryAllocationConnVal() const;

	static uint64_t TotalConnections()
		{ return total_connections; }
	static uint64_t CurrentConnections()
		{ return current_connections; }

	// Returns true if the history was already seen, false otherwise.
	bool CheckHistory(uint32_t mask, char code)
		{
		if ( (hist_seen & mask) == 0 )
			{
			hist_seen |= mask;
			AddHistory(code);
			return false;
			}
		else
			return true;
		}

	// Increments the passed counter and adds it as a history
	// code if it has crossed the next scaling threshold.  Scaling
	// is done in terms of powers of the third argument.
	// Returns true if the threshold was crossed, false otherwise.
	bool ScaledHistoryEntry(char code, uint32_t& counter,
	                        uint32_t& scaling_threshold,
	                        uint32_t scaling_base = 10);

	void HistoryThresholdEvent(EventHandlerPtr e, bool is_orig,
	                           uint32_t threshold);

	void AddHistory(char code)	{ history += code; }

	void DeleteTimer(double t);

	// Sets the root of the analyzer tree as well as the primary PIA.
	void SetRootAnalyzer(zeek::analyzer::TransportLayerAnalyzer* analyzer, analyzer::pia::PIA* pia);
	zeek::analyzer::TransportLayerAnalyzer* GetRootAnalyzer()	{ return root_analyzer; }
	analyzer::pia::PIA* GetPrimaryPIA()	{ return primary_PIA; }

	// Sets the transport protocol in use.
	void SetTransport(TransportProto arg_proto)	{ proto = arg_proto; }

	void SetUID(const Bro::UID &arg_uid)	 { uid = arg_uid; }

	Bro::UID GetUID() const { return uid; }

	const EncapsulationStack* GetEncapsulation() const
		{ return encapsulation; }

	void CheckFlowLabel(bool is_orig, uint32_t flow_label);

	uint32_t GetOrigFlowLabel() { return orig_flow_label; }
	uint32_t GetRespFlowLabel() { return resp_flow_label; }

	bool PermitWeird(const char* name, uint64_t threshold, uint64_t rate,
	                 double duration);

protected:

	// Add the given timer to expire at time t.  If do_expire
	// is true, then the timer is also evaluated when Bro terminates,
	// otherwise not.
	void AddTimer(timer_func timer, double t, bool do_expire,
			TimerType type);

	void RemoveTimer(Timer* t);

	// Allow other classes to access pointers to these:
	friend class ConnectionTimer;

	void InactivityTimer(double t);
	void StatusUpdateTimer(double t);
	void RemoveConnectionTimer(double t);

	NetSessions* sessions;
	ConnIDKey key;
	bool key_valid;

	timer_list timers;

	IPAddr orig_addr;
	IPAddr resp_addr;
	uint32_t orig_port, resp_port;	// in network order
	TransportProto proto;
	uint32_t orig_flow_label, resp_flow_label;	// most recent IPv6 flow labels
	uint32_t vlan, inner_vlan;	// VLAN this connection traverses, if available
	u_char orig_l2_addr[Packet::l2_addr_len];	// Link-layer originator address, if available
	u_char resp_l2_addr[Packet::l2_addr_len];	// Link-layer responder address, if available
	double start_time, last_time;
	double inactivity_timeout;
	zeek::RecordValPtr conn_val;
	LoginConn* login_conn;	// either nil, or this
	const EncapsulationStack* encapsulation; // tunnels
	int suppress_event;	// suppress certain events to once per conn.

	unsigned int installed_status_timer:1;
	unsigned int timers_canceled:1;
	unsigned int is_active:1;
	unsigned int skip:1;
	unsigned int weird:1;
	unsigned int finished:1;
	unsigned int record_packets:1, record_contents:1;
	unsigned int record_current_packet:1, record_current_content:1;
	unsigned int saw_first_orig_packet:1, saw_first_resp_packet:1;
	unsigned int is_successful:1;

	// Count number of connections.
	static uint64_t total_connections;
	static uint64_t current_connections;

	std::string history;
	uint32_t hist_seen;

	zeek::analyzer::TransportLayerAnalyzer* root_analyzer;
	analyzer::pia::PIA* primary_PIA;

	Bro::UID uid;	// Globally unique connection ID.
	WeirdStateMap weird_state;
};

class ConnectionTimer final : public Timer {
public:
	ConnectionTimer(Connection* arg_conn, timer_func arg_timer,
			double arg_t, bool arg_do_expire, TimerType arg_type)
		: Timer(arg_t, arg_type)
		{ Init(arg_conn, arg_timer, arg_do_expire); }
	~ConnectionTimer() override;

	void Dispatch(double t, bool is_expire) override;

protected:
	ConnectionTimer()	{}

	void Init(Connection* conn, timer_func timer, bool do_expire);

	Connection* conn;
	timer_func timer;
	bool do_expire;
};

#define ADD_TIMER(timer, t, do_expire, type) \
	AddTimer(timer_func(timer), (t), (do_expire), (type))
