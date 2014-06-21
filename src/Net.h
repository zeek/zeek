// See the file "COPYING" in the main distribution directory for copyright.

#ifndef net_h
#define net_h

#include "net_util.h"
#include "util.h"
#include "BPF_Program.h"
#include "List.h"
#include "PktSrc.h"
#include "FlowSrc.h"
#include "Func.h"
#include "RemoteSerializer.h"

extern void net_init(name_list& interfaces, name_list& readfiles,
		name_list& netflows, name_list& flowfiles,
		const char* writefile, const char* filter,
		const char* secondary_filter, int do_watchdog);
extern void net_run();
extern void net_get_final_stats();
extern void net_finish(int drain_events);
extern void net_delete();	// Reclaim all memory, etc.
extern void net_packet_dispatch(double t, const struct pcap_pkthdr* hdr,
			const u_char* pkt, int hdr_size,
			PktSrc* src_ps);
extern int net_packet_match(BPF_Program* fp, const u_char* pkt,
			    u_int len, u_int caplen);
extern void expire_timers(PktSrc* src_ps = 0);
extern void termination_signal();

// Functions to temporarily suspend processing of live input (network packets
// and remote events/state). Turning this is on is sure to lead to data loss!
extern void net_suspend_processing();
extern void net_continue_processing();

extern int _processing_suspended;	// don't access directly.
inline bool net_is_processing_suspended()
	{ return _processing_suspended > 0; }

// Whether we're reading live traffic.
extern int reading_live;

// Same but for reading from traces instead.  We have two separate
// variables because it's possible that neither is true, and we're
// instead just running timers (per the variable after this one).
extern int reading_traces;

// True if we have timers scheduled for the future on which we need
// to wait.  "Need to wait" here means that we're running live (though
// perhaps not reading_live, but just running in real-time) as opposed
// to reading a trace (in which case we don't want to wait in real-time
// on future timers).
extern int have_pending_timers;

// If > 0, we are reading from traces but trying to mimic real-time behavior.
// (In this case, both reading_traces and reading_live are true.)  The value
// is the speedup (1 = real-time, 0.5 = half real-time, etc.).
extern double pseudo_realtime;

// When we started processing the current packet and corresponding event
// queue.
extern double processing_start_time;

// When the Bro process was started.
extern double bro_start_time;

// Time at which the Bro process was started with respect to network time,
// i.e. the timestamp of the first packet.
extern double bro_start_network_time;

// True if we're a in the process of cleaning-up just before termination.
extern bool terminating;

// True if the remote serializer is to be activated.
extern bool using_communication;

// Snaplen passed to libpcap.
extern int snaplen;

extern const struct pcap_pkthdr* current_hdr;
extern const u_char* current_pkt;
extern int current_dispatched;
extern int current_hdr_size;
extern double current_timestamp;
extern PktSrc* current_pktsrc;
extern IOSource* current_iosrc;

declare(PList,PktSrc);
extern PList(PktSrc) pkt_srcs;

extern PktDumper* pkt_dumper;	// where to save packets

extern char* writefile;

// Script file we have already scanned (or are in the process of scanning).
// They are identified by inode number.
struct ScannedFile {
	ino_t inode;
	int include_level;
	string name;
	bool skipped;		// This ScannedFile was @unload'd.
	bool prefixes_checked;	// If loading prefixes for this file has been tried.

	ScannedFile(ino_t arg_inode, int arg_include_level, const string& arg_name,
		    bool arg_skipped = false,
		    bool arg_prefixes_checked = false)
			: inode(arg_inode), include_level(arg_include_level),
			name(arg_name), skipped(arg_skipped),
			prefixes_checked(arg_prefixes_checked)
		{ }
};

extern std::list<ScannedFile> files_scanned;
extern std::vector<string> sig_files;

#endif
