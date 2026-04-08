// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h"

#include <optional>
#include <string>

namespace zeek {

class Packet;

namespace iosource {

class IOSource;
class PktSrc;
class PktDumper;

} // namespace iosource

namespace run_state {
namespace detail {

extern void init_run(const std::optional<std::string>& interfaces, const std::optional<std::string>& pcap_input_file,
                     const std::optional<std::string>& pcap_output_file, bool do_watchdog);
extern void run_loop();
extern void get_final_stats();
extern void delete_run(); // Reclaim all memory, etc.
extern void update_network_time(double new_network_time);
extern void dispatch_packet(zeek::Packet* pkt, zeek::iosource::PktSrc* pkt_src);
extern void expire_timers();
extern void zeek_terminate_loop(const char* reason);

/**
 * Returns the packet source for the packet currently being processed. This will
 * return null if some other iosrc is currently active.
 */
extern zeek::iosource::PktSrc* current_packet_source();

extern double check_pseudo_time(const Packet* pkt);

ZEEK_EXTERN_DATA zeek::iosource::IOSource* current_iosrc;
ZEEK_EXTERN_DATA zeek::iosource::PktDumper* pkt_dumper; // where to save packets

// True if we have timers scheduled for the future on which we need
// to wait.  "Need to wait" here means that we're running live (though
// perhaps not reading_live, but just running in real-time) as opposed
// to reading a trace (in which case we don't want to wait in real-time
// on future timers).
ZEEK_EXTERN_DATA bool have_pending_timers;

ZEEK_EXTERN_DATA double first_wallclock;

// Only set in pseudo-realtime mode.
ZEEK_EXTERN_DATA double first_timestamp;
ZEEK_EXTERN_DATA double current_wallclock;
ZEEK_EXTERN_DATA double current_pseudo;

ZEEK_EXTERN_DATA bool zeek_init_done;

ZEEK_EXTERN_DATA bool bare_mode; // True if Zeek was started in bare mode.

} // namespace detail

// Functions to temporarily suspend processing of live input (network packets
// and remote events/state). Turning this is on is sure to lead to data loss!
extern void suspend_processing();
extern void continue_processing();
bool is_processing_suspended();

extern double current_packet_wallclock();

// Whether we're reading live traffic.
ZEEK_EXTERN_DATA bool reading_live;

// Same but for reading from traces instead.  We have two separate
// variables because it's possible that neither is true, and we're
// instead just running timers (per the variable after this one).
ZEEK_EXTERN_DATA bool reading_traces;

// If > 0, we are reading from traces but trying to mimic real-time behavior.
// (In this case, both reading_traces and reading_live are true.)  The value
// is the speedup (1 = real-time, 0.5 = half real-time, etc.).
ZEEK_EXTERN_DATA double pseudo_realtime;

// When we started processing the current packet and corresponding event
// queue.
ZEEK_EXTERN_DATA double processing_start_time;

// When the Zeek process was started.
ZEEK_EXTERN_DATA double zeek_start_time;

// Time at which the Zeek process was started with respect to network time,
// i.e. the timestamp of the first packet.
ZEEK_EXTERN_DATA double zeek_start_network_time;

// Time according to last packet timestamp (or current time)
ZEEK_EXTERN_DATA double network_time;

// True if we're a in the process of cleaning-up just before termination.
ZEEK_EXTERN_DATA bool terminating;

// True if Zeek is currently parsing scripts.
ZEEK_EXTERN_DATA bool is_parsing;

ZEEK_EXTERN_DATA const zeek::Packet* current_pkt;
ZEEK_EXTERN_DATA int current_dispatched;
ZEEK_EXTERN_DATA double current_timestamp;

} // namespace run_state
} // namespace zeek
