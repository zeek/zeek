// $Id: Sessions.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef sessions_h
#define sessions_h

#include "Dict.h"
#include "CompHash.h"
#include "IP.h"
#include "ARP.h"
#include "Frag.h"
#include "PacketFilter.h"
#include "Stats.h"
#include "NetVar.h"

struct pcap_pkthdr;

class Connection;
class ConnID;
class OSFingerprint;
class ConnCompressor;

declare(PDict,Connection);
declare(PDict,FragReassembler);

class Discarder;
class SteppingStoneManager;
class PacketFilter;

class PacketSortElement;

struct SessionStats {
	int num_TCP_conns;
	int num_UDP_conns;
	int num_ICMP_conns;
	int num_fragments;
	int num_packets;
	int num_timers;
	int num_events_queued;
	int num_events_dispatched;

	int max_TCP_conns;
	int max_UDP_conns;
	int max_ICMP_conns;
	int max_fragments;
	int max_timers;
};

// Drains and deletes a timer manager if it hasn't seen any advances
// for an interval timer_mgr_inactivity_timeout.
class TimerMgrExpireTimer : public Timer {
public:
	TimerMgrExpireTimer(double t, TimerMgr* arg_mgr)
		: Timer(t, TIMER_TIMERMGR_EXPIRE)
		{
		mgr = arg_mgr;
		}

	virtual void Dispatch(double t, int is_expire);

protected:
	double interval;
	TimerMgr* mgr;
};

class NetSessions {
public:
	NetSessions();
	~NetSessions();

	// Main entry point for packet processing. Dispatches the packet
	// either through NextPacket() or NextPacketSecondary(), optionally
	// employing the packet sorter first.
	void DispatchPacket(double t, const struct pcap_pkthdr* hdr,
			const u_char* const pkt, int hdr_size,
			PktSrc* src_ps, PacketSortElement* pkt_elem);
	
	void Done();	// call to drain events before destructing

	// Returns a reassembled packet, or nil if there are still
	// some missing fragments.
	FragReassembler* NextFragment(double t, const IP_Hdr* ip,
				const u_char* pkt, uint32 frag_field);

	int Get_OS_From_SYN(struct os_type* retval,
			uint16 tot, uint8 DF_flag, uint8 TTL, uint16 WSS,
			uint8 ocnt, uint8* op, uint16 MSS, uint8 win_scale,
			uint32 tstamp, /* uint8 TOS, */ uint32 quirks,
			uint8 ECN) const;

	bool CompareWithPreviousOSMatch(uint32 addr, int id) const;

	// Looks up the connection referred to by the given Val,
	// which should be a conn_id record.  Returns nil if there's
	// no such connection or the Val is ill-formed.
	Connection* FindConnection(Val* v);

	void Remove(Connection* c);
	void Remove(FragReassembler* f);

	void Insert(Connection* c);

	// Generating connection_pending events for all connections
	// that are still active.
	void Drain();

	// Called periodically to generate statistics reports.
	void HeartBeat(double t);

	void GetStats(SessionStats& s) const;

	void Weird(const char* name,
		const struct pcap_pkthdr* hdr, const u_char* pkt);
	void Weird(const char* name, const IP_Hdr* ip);

	PacketFilter* GetPacketFilter()
		{
		if ( ! packet_filter )
			packet_filter = new PacketFilter(packet_filter_default);
		return packet_filter;
		}

	// Looks up timer manager associated with tag.  If tag is unknown and
	// "create" is true, creates new timer manager and stores it.  Returns
	// global timer manager if tag is nil.
	TimerMgr* LookupTimerMgr(const TimerMgr::Tag* tag, bool create = true);

	void ExpireTimerMgrs();

	SteppingStoneManager* GetSTPManager()	{ return stp_manager; }

	unsigned int CurrentConnections()
		{
		return tcp_conns.Length() + udp_conns.Length() +
			icmp_conns.Length();
		}

	unsigned int ConnectionMemoryUsage();
	unsigned int ConnectionMemoryUsageConnVals();
	unsigned int MemoryAllocation();
	TCPStateStats tcp_stats;	// keeps statistics on TCP states

protected:
	friend class RemoteSerializer;
	friend class ConnCompressor;
	friend class TimerMgrExpireTimer;

	Connection* NewConn(HashKey* k, double t, const ConnID* id,
			const u_char* data, int proto);

	// Check whether the tag of the current packet is consistent with
	// the given connection.  Returns:
	//    -1   if current packet is to be completely ignored.
	//     0   if tag is not consistent and new conn should be instantiated.
	//     1   if tag is consistent, i.e., packet is part of connection.
	int CheckConnectionTag(Connection* conn);

	// Returns true if the port corresonds to an application
	// for which there's a Bro analyzer (even if it might not
	// be used by the present policy script), or it's more
	// generally a likely server port, false otherwise.
	//
	// Note, port is in host order.
	bool IsLikelyServerPort(uint32 port,
				TransportProto transport_proto) const;

	// Upon seeing the first packet of a connection, checks whether
	// we want to analyze it (e.g., we may not want to look at partial
	// connections), and, if yes, whether we should flip the roles of
	// originator and responder (based on known ports or such).
	// Use tcp_flags=0 for non-TCP.
	bool WantConnection(uint16 src_port, uint16 dest_port,
				TransportProto transport_proto,
				uint8 tcp_flags, bool& flip_roles);

	void NextPacket(double t, const struct pcap_pkthdr* hdr,
			const u_char* const pkt, int hdr_size,
			PacketSortElement* pkt_elem);
		
	void DoNextPacket(double t, const struct pcap_pkthdr* hdr,
			const IP_Hdr* ip_hdr, const u_char* const pkt,
			int hdr_size);

	void NextPacketSecondary(double t, const struct pcap_pkthdr* hdr,
			const u_char* const pkt, int hdr_size,
			const PktSrc* src_ps);
	
	// Record the given packet (if a dumper is active).  If len=0
	// then the whole packet is recorded, otherwise just the first
	// len bytes.
	void DumpPacket(const struct pcap_pkthdr* hdr, const u_char* pkt,
			int len=0);

	void Internal(const char* msg, const struct pcap_pkthdr* hdr,
			const u_char* pkt);

	// Builds a record encapsulating a packet.  This should be more
	// general, including the equivalent of a union of tcp/udp/icmp
	// headers .
	Val* BuildHeader(const struct ip* ip);

	CompositeHash* ch;
	PDict(Connection) tcp_conns;
	PDict(Connection) udp_conns;
	PDict(Connection) icmp_conns;
	PDict(FragReassembler) fragments;

	ARP_Analyzer* arp_analyzer;

	SteppingStoneManager* stp_manager;
	Discarder* discarder;
	PacketFilter* packet_filter;
	OSFingerprint* SYN_OS_Fingerprinter;
	int build_backdoor_analyzer;
	int dump_this_packet;	// if true, current packet should be recorded
	int num_packets_processed;
	PacketProfiler* pkt_profiler;

	// We may use independent timer managers for different sets of related
	// activity.  The managers are identified by an unique tag.
	typedef std::map<TimerMgr::Tag, TimerMgr*> TimerMgrMap;
	TimerMgrMap timer_mgrs;
};

// Manager for the currently active sessions.
extern NetSessions* sessions;

#endif
