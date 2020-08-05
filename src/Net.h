// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"

#include <sys/stat.h> // for ino_t

#include <list>
#include <vector>
#include <string>
#include <optional>

ZEEK_FORWARD_DECLARE_NAMESPACED(IOSource, zeek, iosource);
ZEEK_FORWARD_DECLARE_NAMESPACED(PktSrc, zeek, iosource);
ZEEK_FORWARD_DECLARE_NAMESPACED(PktDumper, zeek, iosource);
ZEEK_FORWARD_DECLARE_NAMESPACED(Packet, zeek);

namespace zeek::net {
namespace detail {

extern void net_init(const std::optional<std::string>& interfaces,
                     const std::optional<std::string>& pcap_input_file,
                     const std::optional<std::string>& pcap_output_file,
                     bool do_watchdog);
extern void net_run();
extern void net_get_final_stats();
extern void net_finish(int drain_events);
extern void net_delete();	// Reclaim all memory, etc.
extern void net_update_time(double new_network_time);
extern void net_packet_dispatch(double t, const zeek::Packet* pkt,
                                zeek::iosource::PktSrc* src_ps);
extern void expire_timers(zeek::iosource::PktSrc* src_ps = nullptr);
extern void zeek_terminate_loop(const char* reason);

extern zeek::iosource::PktSrc* current_pktsrc;
extern zeek::iosource::IOSource* current_iosrc;
extern zeek::iosource::PktDumper* pkt_dumper;	// where to save packets

// True if we have timers scheduled for the future on which we need
// to wait.  "Need to wait" here means that we're running live (though
// perhaps not reading_live, but just running in real-time) as opposed
// to reading a trace (in which case we don't want to wait in real-time
// on future timers).
extern bool have_pending_timers;


// Script file we have already scanned (or are in the process of scanning).
// They are identified by normalized realpath.
struct ScannedFile {
	int include_level;
	bool skipped;		// This ScannedFile was @unload'd.
	bool prefixes_checked;	// If loading prefixes for this file has been tried.
	std::string name;
	std::string canonical_path; // normalized, absolute path via realpath()

	ScannedFile(int arg_include_level,
	            std::string arg_name, bool arg_skipped = false,
	            bool arg_prefixes_checked = false);

	/**
	 * Compares the canonical path of this file against every canonical path
	 * in files_scanned and returns whether there's any match.
	 */
	bool AlreadyScanned() const;
};

extern std::list<ScannedFile> files_scanned;
extern std::vector<std::string> sig_files;

} // namespace detail

// Functions to temporarily suspend processing of live input (network packets
// and remote events/state). Turning this is on is sure to lead to data loss!
extern void net_suspend_processing();
extern void net_continue_processing();
bool net_is_processing_suspended();

// Whether we're reading live traffic.
extern bool reading_live;

// Same but for reading from traces instead.  We have two separate
// variables because it's possible that neither is true, and we're
// instead just running timers (per the variable after this one).
extern bool reading_traces;

// If > 0, we are reading from traces but trying to mimic real-time behavior.
// (In this case, both reading_traces and reading_live are true.)  The value
// is the speedup (1 = real-time, 0.5 = half real-time, etc.).
extern double pseudo_realtime;

// When we started processing the current packet and corresponding event
// queue.
extern double processing_start_time;

// When the Bro process was started.
extern double zeek_start_time;

// Time at which the Bro process was started with respect to network time,
// i.e. the timestamp of the first packet.
extern double zeek_start_network_time;

// Time according to last packet timestamp (or current time)
extern double network_time;

// True if we're a in the process of cleaning-up just before termination.
extern bool terminating;

// True if Bro is currently parsing scripts.
extern bool is_parsing;

extern const zeek::Packet* current_pkt;
extern int current_dispatched;
extern double current_timestamp;

} // namespace zeek::net

constexpr auto net_init [[deprecated("Remove in v4.1. Use zeek::net::detail::net_init.")]] = zeek::net::detail::net_init;
constexpr auto net_run [[deprecated("Remove in v4.1. Use zeek::net::detail::net_run.")]] = zeek::net::detail::net_run;
constexpr auto net_get_final_stats [[deprecated("Remove in v4.1. Use zeek::net::detail::net_get_final_stats.")]] = zeek::net::detail::net_get_final_stats;
constexpr auto net_finish [[deprecated("Remove in v4.1. Use zeek::net::detail::net_finish.")]] = zeek::net::detail::net_finish;
constexpr auto net_delete [[deprecated("Remove in v4.1. Use zeek::net::detail::net_delete.")]] = zeek::net::detail::net_delete;
constexpr auto net_update_time [[deprecated("Remove in v4.1. Use zeek::net::detail::net_update_time.")]] = zeek::net::detail::net_update_time;
constexpr auto net_packet_dispatch [[deprecated("Remove in v4.1. Use zeek::net::detail::net_packet_dispatch.")]] = zeek::net::detail::net_packet_dispatch;
constexpr auto expire_timers [[deprecated("Remove in v4.1. Use zeek::net::detail::expire_timers.")]] = zeek::net::detail::expire_timers;
constexpr auto zeek_terminate_loop [[deprecated("Remove in v4.1. Use zeek::net::detail::zeek_terminate_loop.")]] = zeek::net::detail::zeek_terminate_loop;
extern zeek::iosource::PktSrc*& current_pktsrc [[deprecated("Remove in v4.1. Use zeek::net::detail::current_pktsrc.")]];
extern zeek::iosource::IOSource*& current_iosrc [[deprecated("Remove in v4.1. Use zeek::net::detail::current_iosrc.")]];
extern zeek::iosource::PktDumper*& pkt_dumper [[deprecated("Remove in v4.1. Use zeek::net::detail::pkt_dumper.")]];
extern bool& have_pending_timers [[deprecated("Remove in v4.1. Use zeek::net::detail::have_pending_timers.")]];

constexpr auto net_suspend_processing [[deprecated("Remove in v4.1. Use zeek::net::net_suspend_processing.")]] = zeek::net::net_suspend_processing;
constexpr auto net_continue_processing [[deprecated("Remove in v4.1. Use zeek::net::net_continue_processing.")]] = zeek::net::net_continue_processing;
constexpr auto net_is_processing_suspended [[deprecated("Remove in v4.1. Use zeek::net::net_is_processing_suspended.")]] = zeek::net::net_is_processing_suspended;

extern bool& reading_live [[deprecated("Remove in v4.1. Use zeek::net::reading_live.")]];
extern bool& reading_traces [[deprecated("Remove in v4.1. Use zeek::net::reading_traces.")]];
extern double& pseudo_realtime [[deprecated("Remove in v4.1. Use zeek::net::pseudo_realtime.")]];
extern double& processing_start_time [[deprecated("Remove in v4.1. Use zeek::net::processing_start_time.")]];
extern double& bro_start_time [[deprecated("Remove in v4.1. Use zeek::net::zeek_start_time.")]];
extern double& bro_start_network_time [[deprecated("Remove in v4.1. Use zeek::net::zeek_start_network_time.")]];
extern bool& terminating [[deprecated("Remove in v4.1. Use zeek::net::terminating.")]];
extern bool& is_parsing [[deprecated("Remove in v4.1. Use zeek::net::is_parsing.")]];
extern const zeek::Packet*& current_pkt [[deprecated("Remove in v4.1. Use zeek::net::current_pkt.")]];
extern int& current_dispatched [[deprecated("Remove in v4.1. Use zeek::net::current_dispatched.")]];
extern double& current_timestamp [[deprecated("Remove in v4.1. Use zeek::net::current_timestamp.")]];

using ScannedFile [[deprecated("Remove in v4.1. Use zeek::net::detail::ScannedFile.")]] = zeek::net::detail::ScannedFile;
extern std::list<zeek::net::detail::ScannedFile>& files_scanned [[deprecated("Remove in v4.1. Use zeek::net::detail::files_scanned.")]];
extern std::vector<std::string>& sig_files [[deprecated("Remove in v4.1. Use zeek::net::detail::sig_files.")]];
