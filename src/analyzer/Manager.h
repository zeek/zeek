// The central management unit for dynamic analyzer selection.

#ifndef ANALYZER_MANAGER_H
#define ANALYZER_MANAGER_H

#include <queue>

#include "Tag.h"
#include "PluginComponent.h"

#include "Analyzer.h"
#include "../Dict.h"
#include "../net_util.h"
#include "../IP.h"

namespace analyzer {

// Manager debug logging, which includes the connection id into the message.
#ifdef DEBUG
# define DBG_DPD(conn, txt) \
	DBG_LOG(DBG_DPD, "%s " txt, \
		fmt_conn_id(conn->OrigAddr(), ntohs(conn->OrigPort()), \
		conn->RespAddr(), ntohs(conn->RespPort())));
# define DBG_DPD_ARGS(conn, fmt, args...) \
	DBG_LOG(DBG_DPD, "%s " fmt, \
		fmt_conn_id(conn->OrigAddr(), ntohs(conn->OrigPort()), \
		conn->RespAddr(), ntohs(conn->RespPort())), ##args);
#else
# define DBG_DPD(conn, txt)
# define DBG_DPD_ARGS(conn, fmt, args...)
#endif

// Map index to assign expected connections to analyzers.
class ExpectedConn {
public:
	ExpectedConn(const IPAddr& _orig, const IPAddr& _resp,
			uint16 _resp_p, uint16 _proto);

	ExpectedConn(const ExpectedConn& c);

	IPAddr orig;
	IPAddr resp;
	uint16 resp_p;
	uint16 proto;
};

// Associates an analyzer for an expected future connection.
class AssignedAnalyzer {
public:
	AssignedAnalyzer(const ExpectedConn& c)
	: conn(c)	{ }

	ExpectedConn conn;
	Tag analyzer;
	double timeout;
	void* cookie;
	bool deleted;

	static bool compare(const AssignedAnalyzer* a1, const AssignedAnalyzer* a2)
		{ return a1->timeout > a2->timeout; }
};

declare(PDict, AssignedAnalyzer);

class Manager {
public:
	Manager();
	~Manager();

	void Init(); // Called before script's are parsed.
	void Done();
	void DumpDebug(); // Called after bro_init() events.

	bool EnableAnalyzer(Tag tag);
	bool EnableAnalyzer(EnumVal* tag);

	bool DisableAnalyzer(Tag tag);
	bool DisableAnalyzer(EnumVal* tag);

	bool IsEnabled(Tag tag);
	bool IsEnabled(EnumVal* tag);

	bool RegisterAnalyzerForPort(EnumVal* tag, PortVal* port);
	bool RegisterAnalyzerForPort(Tag tag, TransportProto proto, uint32 port);

	bool UnregisterAnalyzerForPort(EnumVal* tag, PortVal* port);
	bool UnregisterAnalyzerForPort(Tag tag, TransportProto proto, uint32 port);

	Analyzer* InstantiateAnalyzer(Tag tag, Connection* c); // Null if disabled.

	string GetAnalyzerName(Tag tag);
	string GetAnalyzerName(Val* val);
	Tag GetAnalyzerTag(const string& name); // Tag::ERROR when not known.
	Tag GetAnalyzerTag(const char* name); // Tag::ERROR when not known.

	EnumType* GetTagEnumType();

	// Given info about the first packet, build initial analyzer tree.
	//
	// It would be more flexible if we simply pass in the IP header and
	// then extract the information we need.  However, when this method
	// is called from the session management, protocol and ports have
	// already been extracted there and it would be a waste to do it
	// again.
	//
	// Returns 0 if we can't build a tree (e.g., because the necessary
	// analyzers have not been converted to the Manager framework yet...)
	bool BuildInitialAnalyzerTree(TransportProto proto, Connection* conn,
					const u_char* data);

	// Schedules a particular analyzer for an upcoming connection. 0 acts
	// as a wildcard for orig.  (Cookie is currently unused. Eventually,
	// we may pass it on to the analyzer).
	void ExpectConnection(const IPAddr& orig, const IPAddr& resp, uint16 resp_p,
				TransportProto proto, Tag::Tag analyzer,
				double timeout, void* cookie);

	void ExpectConnection(const IPAddr& orig, const IPAddr& resp, uint16 resp_p,
				TransportProto proto, const string& analyzer,
				double timeout, void* cookie);

	void ExpectConnection(const IPAddr& orig, const IPAddr& resp, PortVal* resp_p,
				Val* val, double timeout, void* cookie);

	// Activates signature matching for protocol detection. (Called when
	// an Manager signatures is found.)
	void ActivateSigs()		{ sigs_activated = true; }
	bool SigsActivated() const	{ return sigs_activated; }

private:
	typedef set<Tag> tag_set;
	typedef map<string, PluginComponent*> analyzer_map_by_name;
	typedef map<Tag, PluginComponent*>  analyzer_map_by_tag;
	typedef map<int, PluginComponent*>  analyzer_map_by_val;
	typedef map<uint32, tag_set*> analyzer_map_by_port;

	void RegisterAnalyzerComponent(PluginComponent* component); // Takes ownership.

	PluginComponent* Lookup(const string& name);
	PluginComponent* Lookup(const char* name);
	PluginComponent* Lookup(const Tag& tag);
	PluginComponent* Lookup(EnumVal* val);

	tag_set* LookupPort(PortVal* val, bool add_if_not_found);
	tag_set* LookupPort(TransportProto proto, uint32 port, bool add_if_not_found);

	// Return analyzer if any has been scheduled with ExpectConnection()
	// Tag::::Error if none.
	Tag GetExpected(int proto, const Connection* conn);

	analyzer_map_by_port analyzers_by_port_tcp;
	analyzer_map_by_port analyzers_by_port_udp;
	analyzer_map_by_name analyzers_by_name;
	analyzer_map_by_tag  analyzers_by_tag;
	analyzer_map_by_val  analyzers_by_val;

	Tag analyzer_backdoor;
	Tag analyzer_connsize;
	Tag analyzer_interconn;
	Tag analyzer_stepping;
	Tag analyzer_tcpstats;

	EnumType* tag_enum_type;

	// True if signature-matching has been activated.
	bool sigs_activated;

	PDict(AssignedAnalyzer) expected_conns;

	typedef priority_queue<
			AssignedAnalyzer*,
			vector<AssignedAnalyzer*>,
			bool (*)(const AssignedAnalyzer*,
					const AssignedAnalyzer*)> conn_queue;
	conn_queue expected_conns_queue;
};

}

extern analyzer::Manager* analyzer_mgr;

#endif
