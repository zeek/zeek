// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

// These includes are needed for the inclusion of the bif headers at the end
// of this file.
#include "zeek/zeek-config.h"

#include "zeek/EventRegistry.h"
#include "zeek/Val.h"

namespace zeek::detail {

ZEEK_EXTERN_DATA double watchdog_interval;

ZEEK_EXTERN_DATA int max_timer_expires;

ZEEK_EXTERN_DATA int ignore_checksums;
ZEEK_EXTERN_DATA int partial_connection_ok;
ZEEK_EXTERN_DATA int tcp_SYN_ack_ok;
ZEEK_EXTERN_DATA int tcp_match_undelivered;

ZEEK_EXTERN_DATA double frag_timeout;

ZEEK_EXTERN_DATA double tcp_SYN_timeout;
ZEEK_EXTERN_DATA double tcp_session_timer;
ZEEK_EXTERN_DATA double tcp_connection_linger;
ZEEK_EXTERN_DATA double tcp_attempt_delay;
ZEEK_EXTERN_DATA double tcp_close_delay;
ZEEK_EXTERN_DATA double tcp_partial_close_delay;
ZEEK_EXTERN_DATA double tcp_reset_delay;

ZEEK_EXTERN_DATA int tcp_max_initial_window;
ZEEK_EXTERN_DATA int tcp_max_above_hole_without_any_acks;
ZEEK_EXTERN_DATA int tcp_excessive_data_without_further_acks;
ZEEK_EXTERN_DATA int tcp_max_old_segments;

ZEEK_EXTERN_DATA double non_analyzed_lifetime;
ZEEK_EXTERN_DATA double tcp_inactivity_timeout;
ZEEK_EXTERN_DATA double udp_inactivity_timeout;
ZEEK_EXTERN_DATA double icmp_inactivity_timeout;
ZEEK_EXTERN_DATA double unknown_ip_inactivity_timeout;

ZEEK_EXTERN_DATA int tcp_storm_thresh;
ZEEK_EXTERN_DATA double tcp_storm_interarrival_thresh;
ZEEK_EXTERN_DATA bool tcp_content_deliver_all_orig;
ZEEK_EXTERN_DATA bool tcp_content_deliver_all_resp;

ZEEK_EXTERN_DATA bool udp_content_deliver_all_orig;
ZEEK_EXTERN_DATA bool udp_content_deliver_all_resp;
ZEEK_EXTERN_DATA bool udp_content_delivery_ports_use_resp;

ZEEK_EXTERN_DATA double dns_session_timeout;
ZEEK_EXTERN_DATA double rpc_timeout;

ZEEK_EXTERN_DATA int mime_segment_length;
ZEEK_EXTERN_DATA int mime_segment_overlap_length;

ZEEK_EXTERN_DATA int http_entity_data_delivery_size;
ZEEK_EXTERN_DATA int truncate_http_URI;

ZEEK_EXTERN_DATA int dns_skip_all_auth;
ZEEK_EXTERN_DATA int dns_skip_all_addl;
ZEEK_EXTERN_DATA int dns_max_queries;
ZEEK_EXTERN_DATA int dns_max_compression_chain_depth;

ZEEK_EXTERN_DATA double table_expire_interval;
ZEEK_EXTERN_DATA double table_expire_delay;
ZEEK_EXTERN_DATA int table_incremental_step;

ZEEK_EXTERN_DATA int orig_addr_anonymization, resp_addr_anonymization;
ZEEK_EXTERN_DATA int other_addr_anonymization;

ZEEK_EXTERN_DATA double connection_status_update_interval;

ZEEK_EXTERN_DATA double profiling_interval;
ZEEK_EXTERN_DATA int expensive_profiling_multiple;

ZEEK_EXTERN_DATA int pkt_profile_mode;
ZEEK_EXTERN_DATA double pkt_profile_freq;

ZEEK_EXTERN_DATA int packet_filter_default;

ZEEK_EXTERN_DATA int sig_max_group_size;

ZEEK_EXTERN_DATA int dpd_reassemble_first_packets;
ZEEK_EXTERN_DATA int dpd_buffer_size;
ZEEK_EXTERN_DATA int dpd_max_packets;
ZEEK_EXTERN_DATA int dpd_match_only_beginning;
ZEEK_EXTERN_DATA int dpd_late_match_stop;
ZEEK_EXTERN_DATA int dpd_ignore_ports;

ZEEK_EXTERN_DATA int record_all_packets;

ZEEK_EXTERN_DATA zeek_uint_t bits_per_uid;

ZEEK_EXTERN_DATA zeek_uint_t tunnel_max_changes_per_connection;

// Initializes globals that don't pertain to network/event analysis.
extern void init_general_global_var();

extern void init_event_handlers();
extern void init_net_var();
extern void init_builtin_types();

} // namespace zeek::detail

#include "zeek/const.bif.netvar_h"
#include "zeek/event.bif.netvar_h"
#include "zeek/packet_analysis.bif.netvar_h"
#include "zeek/reporter.bif.netvar_h"
#include "zeek/supervisor.bif.netvar_h"
#include "zeek/telemetry_consts.bif.netvar_h"
#include "zeek/telemetry_types.bif.netvar_h"
#include "zeek/types.bif.netvar_h"
