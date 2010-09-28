// $Id: Conn.h 6916 2009-09-24 20:48:36Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef conn_h
#define conn_h

#include <sys/types.h>

#include "Dict.h"
#include "Val.h"
#include "Timer.h"
#include "Serializer.h"
#include "PersistenceSerializer.h"
#include "RuleMatcher.h"
#include "AnalyzerTags.h"

class Connection;
class ConnectionTimer;
class NetSessions;
class LoginConn;
class RuleHdrTest;
class Specific_RE_Matcher;
class TransportLayerAnalyzer;
class RuleEndpointState;
class Rewriter;

typedef enum {
	NUL_IN_LINE,
	SINGULAR_CR,
	SINGULAR_LF,
	NUM_EVENTS_TO_FLAG,
} ConnEventToFlag;

typedef void (Connection::*timer_func)(double t);

struct ConnID {
	const uint32* src_addr;
	const uint32* dst_addr;
	uint32 src_port;
	uint32 dst_port;
	bool is_one_way;	// if true, don't canonicalize

	// Returns a ListVal suitable for looking up a connection in
	// a hash table.  addr/ports are expected to be in network order.
	// Unless is_one_way is true, the lookup sorts src and dst,
	// so src_addr/src_port and dst_addr/dst_port just have to
	// reflect the two different sides of the connection,
	// neither has to be the particular source/destination
	// or originator/responder.
	HashKey* BuildConnKey() const;

	// The structure used internally for hashing.
	struct Key {
		uint32 ip1[NUM_ADDR_WORDS];
		uint32 ip2[NUM_ADDR_WORDS];
		uint16 port1;
		uint16 port2;
	};
};

static inline int addr_port_canon_lt(const uint32* a1, uint32 p1,
					const uint32* a2, uint32 p2)
	{
#ifdef BROv6
	// Because it's a canonical ordering, not a strict ordering,
	// we can choose to give more weight to the least significant
	// word than to the most significant word.  This matters
	// because for the common case of IPv4 addresses embedded in
	// a IPv6 address, the top three words are identical, so we can
	// save a few cycles by first testing the bottom word.
	return a1[3] < a2[3] ||
		(a1[3] == a2[3] &&
		 (a1[2] < a2[2] ||
		  (a1[2] == a2[2] &&
		   (a1[1] < a2[1] ||
		    (a1[1] == a2[1] &&
		     (a1[0] < a2[0] ||
		      (a1[0] == a2[0] &&
		       p1 < p2)))))));
#else
	return *a1 < *a2 || (*a1 == *a2 && p1 < p2);
#endif
	}

class Analyzer;

class Connection : public BroObj {
public:
	Connection(NetSessions* s, HashKey* k, double t, const ConnID* id);
	virtual ~Connection();

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
	void NextPacket(double t, int is_orig,
			const IP_Hdr* ip, int len, int caplen,
			const u_char*& data,
			int& record_packet, int& record_content,
			// arguments for reproducing packets
			const struct pcap_pkthdr* hdr,
			const u_char* const pkt,
			int hdr_size);

	HashKey* Key() const			{ return key; }
	void ClearKey()				{ key = 0; }

	double StartTime() const		{ return start_time; }
	void  SetStartTime(double t)		{ start_time = t; }
	double LastTime() const			{ return last_time; }
	void SetLastTime(double t) 		{ last_time = t; }

	const uint32* OrigAddr() const		{ return orig_addr; }
	const uint32* RespAddr() const		{ return resp_addr; }

	uint32 OrigPort() const			{ return orig_port; }
	uint32 RespPort() const			{ return resp_port; }

	void FlipRoles();

	Analyzer* FindAnalyzer(AnalyzerID id);
	Analyzer* FindAnalyzer(AnalyzerTag::Tag tag);	// find first in tree.

	TransportProto ConnTransport() const { return proto; }

	// If we are rewriting the trace of the connection, then we do
	// not record original packets. We are rewriting if at least one,
	// then the analyzer is rewriting.
	int RewritingTrace();

	// If we are rewriting trace, we need a handle to the rewriter.
	// Returns 0 if not rewriting.  (Note that if multiple analyzers
	// want to rewrite, only one of them is returned.  It's undefined
	// which one.)
	Rewriter* TraceRewriter() const;

	// True if we should record subsequent packets (either headers or
	// in their entirety, depending on record_contents).  We still
	// record subsequent SYN/FIN/RST, regardless of how this is set.
	int RecordPackets() const		{ return record_packets; }
	void SetRecordPackets(int do_record)	{ record_packets = do_record; }

	// True if we should record full packets for this connection,
	// false if we should just record headers.
	int RecordContents() const		{ return record_contents; }
	void SetRecordContents(int do_record)	{ record_contents = do_record; }

	// Set whether to record *current* packet header/full.
	void SetRecordCurrentPacket(int do_record)
		{ record_current_packet = do_record; }
	void SetRecordCurrentContent(int do_record)
		{ record_current_content = do_record; }

	// FIXME: Now this is in Analyzer and should eventually be removed here.
	//
	// If true, skip processing of remainder of connection.  Note
	// that this does not in itself imply that record_packets is false;
	// we might want instead to process the connection off-line.
	void SetSkip(int do_skip)		{ skip = do_skip; }
	int Skipping() const			{ return skip; }

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

	RecordVal* BuildConnVal();
	void AppendAddl(const char* str);

	LoginConn* AsLoginConn()		{ return login_conn; }

	void Match(Rule::PatternType type, const u_char* data, int len,
			bool is_orig, bool bol, bool eol, bool clear_state);

	// Tries really hard to extract a program name and a version.
	Val* BuildVersionVal(const char* s, int len);

	// Raises a software_version_found event based on the
	// given string (returns false if it's not parseable).
	int VersionFoundEvent(const uint32* addr, const char* s, int len,
				Analyzer* analyzer = 0);

	// Raises a software_unparsed_version_found event.
	int UnparsedVersionFoundEvent(const uint32* addr,
			const char* full_descr, int len, Analyzer* analyzer);
	
	void Event(EventHandlerPtr f, Analyzer* analyzer, const char* name = 0);
	void Event(EventHandlerPtr f, Analyzer* analyzer, Val* v1, Val* v2 = 0);
	void ConnectionEvent(EventHandlerPtr f, Analyzer* analyzer,
				val_list* vl);

	void Weird(const char* name);
	void Weird(const char* name, const char* addl);
	void Weird(const char* name, int addl_len, const char* addl);
	bool DidWeird() const	{ return weird != 0; }

	// Cancel all associated timers.
	void CancelTimers();

	inline int FlagEvent(ConnEventToFlag e)
		{
		if ( e >= 0 && e < NUM_EVENTS_TO_FLAG )
			{
			if ( suppress_event & (1 << e) )
				return 0;
			suppress_event |= 1 << e;
			}

		return 1;
		}

	void MakePersistent()
		{
		persistent = 1;
		persistence_serializer->Register(this);
		}

	bool IsPersistent()	{ return persistent; }

	void Describe(ODesc* d) const;

	TimerMgr* GetTimerMgr() const;

	// Returns true if connection has been received externally.
	bool IsExternal() const	{ return conn_timer_mgr != 0; }

	bool Serialize(SerialInfo* info) const;
	static Connection* Unserialize(UnserialInfo* info);

	DECLARE_SERIAL(Connection);

	// Statistics.

	// Just a lower bound.
	unsigned int MemoryAllocation() const;
	unsigned int MemoryAllocationConnVal() const;

	static unsigned int TotalConnections()
		{ return total_connections; }
	static unsigned int CurrentConnections()
		{ return current_connections; }
	static unsigned int CurrentExternalConnections()
		{ return external_connections; }

	// Returns true if the history was already seen, false otherwise.
	int CheckHistory(uint32 mask, char code)
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

	void AddHistory(char code)	{ history += code; }

	void DeleteTimer(double t);

	// Sets the root of the analyzer tree as well as the primary PIA.
	void SetRootAnalyzer(TransportLayerAnalyzer* analyzer, PIA* pia);
	TransportLayerAnalyzer* GetRootAnalyzer()	{ return root_analyzer; }
	PIA* GetPrimaryPIA()	{ return primary_PIA; }

	// Sets the transport protocol in use.
	void SetTransport(TransportProto arg_proto)	{ proto = arg_proto; }

	// If the connection compressor is activated, we need a special memory
	// layout for connections. (See ConnCompressor.h)
	void* operator new(size_t size)
		{
		if ( ! use_connection_compressor )
			return ::operator new(size);

		void* c = ::operator new(size + 4);

		// We have to turn off the is_pending bit.  By setting the
		// first four bytes to zero, we'll achieve this.
		*((uint32*) c) = 0;

		return ((char *) c) + 4;
		}

	void operator delete(void* ptr)
		{
		if ( ! use_connection_compressor )
			::operator delete(ptr);
		else
			::operator delete(((char*) ptr) - 4);
		}

protected:
	Connection()	{ persistent = 0; }

	// Add the given timer to expire at time t.  If do_expire
	// is true, then the timer is also evaluated when Bro terminates,
	// otherwise not.
	void AddTimer(timer_func timer, double t, int do_expire,
			TimerType type);

	void RemoveTimer(Timer* t);

	// Allow other classes to access pointers to these:
	friend class ConnectionTimer;

	void InactivityTimer(double t);
	void StatusUpdateTimer(double t);
	void RemoveConnectionTimer(double t);

	NetSessions* sessions;
	HashKey* key;

	// Timer manager to use for this conn (or nil).
	TimerMgr::Tag* conn_timer_mgr;
	timer_list timers;

	uint32 orig_addr[NUM_ADDR_WORDS];	// in network order
	uint32 resp_addr[NUM_ADDR_WORDS];	// in network order
	uint32 orig_port, resp_port;	// in network order
	TransportProto proto;
	double start_time, last_time;
	double inactivity_timeout;
	RecordVal* conn_val;
	RecordVal* orig_endp;
	RecordVal* resp_endp;
	LoginConn* login_conn;	// either nil, or this
	int suppress_event;	// suppress certain events to once per conn.

	unsigned int installed_status_timer:1;
	unsigned int timers_canceled:1;
	unsigned int is_active:1;
	unsigned int skip:1;
	unsigned int weird:1;
	unsigned int finished:1;
	unsigned int record_packets:1, record_contents:1;
	unsigned int persistent:1;
	unsigned int record_current_packet:1, record_current_content:1;

	// Count number of connections.
	static unsigned int total_connections;
	static unsigned int current_connections;
	static unsigned int external_connections;

	string history;
	uint32 hist_seen;

	TransportLayerAnalyzer* root_analyzer;
	PIA* primary_PIA;
};

class ConnectionTimer : public Timer {
public:
	ConnectionTimer(Connection* arg_conn, timer_func arg_timer,
			double arg_t, int arg_do_expire, TimerType arg_type)
		: Timer(arg_t, arg_type)
		{ Init(arg_conn, arg_timer, arg_do_expire); }
	virtual ~ConnectionTimer();

	void Dispatch(double t, int is_expire);

protected:
	ConnectionTimer()	{}

	void Init(Connection* conn, timer_func timer, int do_expire);

	DECLARE_SERIAL(ConnectionTimer);

	Connection* conn;
	timer_func timer;
	int do_expire;
};

#define ADD_TIMER(timer, t, do_expire, type) \
	AddTimer(timer_func(timer), (t), (do_expire), (type))

#endif
