// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"

#include <string>
#include <optional>

ZEEK_FORWARD_DECLARE_NAMESPACED(IOSource, zeek, iosource);
ZEEK_FORWARD_DECLARE_NAMESPACED(PktSrc, zeek, iosource);
ZEEK_FORWARD_DECLARE_NAMESPACED(PktDumper, zeek, iosource);
ZEEK_FORWARD_DECLARE_NAMESPACED(Packet, zeek);

namespace zeek::run_state {
namespace detail {

extern void init_run(const std::optional<std::string>& interfaces,
                     const std::optional<std::string>& pcap_input_file,
                     const std::optional<std::string>& pcap_output_file,
                     bool do_watchdog);
extern void run_loop();
extern void get_final_stats();
extern void finish_run(int drain_events);
extern void delete_run();	// Reclaim all memory, etc.
extern void update_network_time(double new_network_time);
extern void dispatch_packet(zeek::Packet* pkt, zeek::iosource::PktSrc* pkt_src);
extern void expire_timers();
extern void zeek_terminate_loop(const char* reason);

/**
 * Returns the packet source for the packet currently being processed. This will
 * return null if some other iosrc is currently active.
 */
extern zeek::iosource::PktSrc* current_packet_source();

extern double check_pseudo_time(const Packet *pkt);

extern zeek::iosource::PktSrc* current_pktsrc [[deprecated("Remove in v4.1. Use zeek::run_state::detail::get_current_pktsrc().")]];
extern zeek::iosource::IOSource* current_iosrc;
extern zeek::iosource::PktDumper* pkt_dumper;	// where to save packets

// True if we have timers scheduled for the future on which we need
// to wait.  "Need to wait" here means that we're running live (though
// perhaps not reading_live, but just running in real-time) as opposed
// to reading a trace (in which case we don't want to wait in real-time
// on future timers).
extern bool have_pending_timers;

extern double first_wallclock;

// Only set in pseudo-realtime mode.
extern double first_timestamp;
extern double current_wallclock;
extern double current_pseudo;

extern bool zeek_init_done;

} // namespace detail

// Functions to temporarily suspend processing of live input (network packets
// and remote events/state). Turning this is on is sure to lead to data loss!
extern void suspend_processing();
extern void continue_processing();
bool is_processing_suspended();

extern double current_packet_timestamp();
extern double current_packet_wallclock();

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

} // namespace zeek::run_state

constexpr auto net_init [[deprecated("Remove in v4.1. Use zeek::run_state::detail::init_run.")]] = zeek::run_state::detail::init_run;
constexpr auto net_run [[deprecated("Remove in v4.1. Use zeek::run_state::detail::run_run.")]] = zeek::run_state::detail::run_loop;
constexpr auto net_get_final_stats [[deprecated("Remove in v4.1. Use zeek::run_state::detail::get_final_stats.")]] = zeek::run_state::detail::get_final_stats;
constexpr auto net_finish [[deprecated("Remove in v4.1. Use zeek::run_state::detail::finish_run.")]] = zeek::run_state::detail::finish_run;
constexpr auto net_delete [[deprecated("Remove in v4.1. Use zeek::run_state::detail::delete_run.")]] = zeek::run_state::detail::delete_run;
constexpr auto net_update_time [[deprecated("Remove in v4.1. Use zeek::run_state::detail::update_network_time.")]] = zeek::run_state::detail::update_network_time;
constexpr auto net_packet_dispatch [[deprecated("Remove in v4.1. Use zeek::run_state::detail::dispatch_packet.")]] = zeek::run_state::detail::dispatch_packet;
constexpr auto expire_timers [[deprecated("Remove in v4.1. Use zeek::run_state::detail::expire_timers.")]] = zeek::run_state::detail::expire_timers;
constexpr auto zeek_terminate_loop [[deprecated("Remove in v4.1. Use zeek::run_state::detail::zeek_terminate_loop.")]] = zeek::run_state::detail::zeek_terminate_loop;
extern zeek::iosource::PktSrc*& current_pktsrc [[deprecated("Remove in v4.1. Use zeek::run_state::detail::get_current_pktsrc().")]];
extern zeek::iosource::IOSource*& current_iosrc [[deprecated("Remove in v4.1. Use zeek::run_state::detail::current_iosrc.")]];
extern zeek::iosource::PktDumper*& pkt_dumper [[deprecated("Remove in v4.1. Use zeek::run_state::detail::pkt_dumper.")]];
extern bool& have_pending_timers [[deprecated("Remove in v4.1. Use zeek::run_state::detail::have_pending_timers.")]];

constexpr auto net_suspend_processing [[deprecated("Remove in v4.1. Use zeek::run_state::suspend_processing.")]] = zeek::run_state::suspend_processing;
constexpr auto net_continue_processing [[deprecated("Remove in v4.1. Use zeek::run_state::continue_processing.")]] = zeek::run_state::continue_processing;
constexpr auto net_is_processing_suspended [[deprecated("Remove in v4.1. Use zeek::run_state::is_processing_suspended.")]] = zeek::run_state::is_processing_suspended;

extern bool& reading_live [[deprecated("Remove in v4.1. Use zeek::run_state::reading_live.")]];
extern bool& reading_traces [[deprecated("Remove in v4.1. Use zeek::run_state::reading_traces.")]];
extern double& pseudo_realtime [[deprecated("Remove in v4.1. Use zeek::run_state::pseudo_realtime.")]];
extern double& processing_start_time [[deprecated("Remove in v4.1. Use zeek::run_state::processing_start_time.")]];
extern double& bro_start_time [[deprecated("Remove in v4.1. Use zeek::run_state::zeek_start_time.")]];
extern double& bro_start_network_time [[deprecated("Remove in v4.1. Use zeek::run_state::zeek_start_network_time.")]];
extern bool& terminating [[deprecated("Remove in v4.1. Use zeek::run_state::terminating.")]];
extern bool& is_parsing [[deprecated("Remove in v4.1. Use zeek::run_state::is_parsing.")]];
extern const zeek::Packet*& current_pkt [[deprecated("Remove in v4.1. Use zeek::run_state::current_pkt.")]];
extern int& current_dispatched [[deprecated("Remove in v4.1. Use zeek::run_state::current_dispatched.")]];
extern double& current_timestamp [[deprecated("Remove in v4.1. Use zeek::run_state::current_timestamp.")]];
