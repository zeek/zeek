// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Val.h"
#include "zeek/EventRegistry.h"
#include "zeek/Stats.h"

namespace zeek::detail {

extern int watchdog_interval;

extern int max_timer_expires;

extern int ignore_checksums;
extern int partial_connection_ok;
extern int tcp_SYN_ack_ok;
extern int tcp_match_undelivered;

extern double frag_timeout;

extern double tcp_SYN_timeout;
extern double tcp_session_timer;
extern double tcp_connection_linger;
extern double tcp_attempt_delay;
extern double tcp_close_delay;
extern double tcp_partial_close_delay;
extern double tcp_reset_delay;

extern int tcp_max_initial_window;
extern int tcp_max_above_hole_without_any_acks;
extern int tcp_excessive_data_without_further_acks;
extern int tcp_max_old_segments;

extern double non_analyzed_lifetime;
extern double tcp_inactivity_timeout;
extern double udp_inactivity_timeout;
extern double icmp_inactivity_timeout;

extern int tcp_storm_thresh;
extern double tcp_storm_interarrival_thresh;
extern bool tcp_content_deliver_all_orig;
extern bool tcp_content_deliver_all_resp;

extern bool udp_content_deliver_all_orig;
extern bool udp_content_deliver_all_resp;
extern bool udp_content_delivery_ports_use_resp;

extern double dns_session_timeout;
extern double rpc_timeout;

extern int mime_segment_length;
extern int mime_segment_overlap_length;

extern int http_entity_data_delivery_size;
extern int truncate_http_URI;

extern int dns_skip_all_auth;
extern int dns_skip_all_addl;
extern int dns_max_queries;

extern double stp_delta;
extern double stp_idle_min;
extern double table_expire_interval;
extern double table_expire_delay;
extern int table_incremental_step;

extern int orig_addr_anonymization, resp_addr_anonymization;
extern int other_addr_anonymization;

extern double connection_status_update_interval;

extern double profiling_interval;
extern int expensive_profiling_multiple;

extern int segment_profiling;
extern int pkt_profile_mode;
extern double pkt_profile_freq;
extern int load_sample_freq;

extern int packet_filter_default;

extern int sig_max_group_size;

extern int dpd_reassemble_first_packets;
extern int dpd_buffer_size;
extern int dpd_match_only_beginning;
extern int dpd_late_match_stop;
extern int dpd_ignore_ports;

extern int check_for_unused_event_handlers;

extern double timer_mgr_inactivity_timeout;

extern int record_all_packets;

extern bro_uint_t bits_per_uid;

// Initializes globals that don't pertain to network/event analysis.
extern void init_general_global_var();

extern void init_event_handlers();
extern void init_net_var();
extern void init_builtin_types();

} // namespace zeek::detail

#include "const.bif.netvar_h"
#include "types.bif.netvar_h"
#include "event.bif.netvar_h"
#include "reporter.bif.netvar_h"
#include "supervisor.bif.netvar_h"
#include "packet_analysis.bif.netvar_h"
