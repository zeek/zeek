// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Val.h"
#include "Func.h"
#include "EventRegistry.h"
#include "Stats.h"

[[deprecated("Remove in v4.1.  Use zeek::id::conn_id.")]]
extern RecordType* conn_id;
[[deprecated("Remove in v4.1.  Use zeek::id::endpoint.")]]
extern RecordType* endpoint;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* endpoint_stats;
[[deprecated("Remove in v4.1.  Use zeek::id::connection.")]]
extern RecordType* connection_type;
[[deprecated("Remove in v4.1.  Use zeek::id::fa_file.")]]
extern RecordType* fa_file_type;
[[deprecated("Remove in v4.1.  Use zeek::id::fa_metadata.")]]
extern RecordType* fa_metadata_type;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* icmp_conn;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* icmp_context;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* signature_state;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* SYN_packet;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* pcap_packet;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* raw_pkt_hdr_type;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* l2_hdr_type;
[[deprecated("Remove in v4.1.  Use zeek::id::transport_proto.")]]
extern EnumType* transport_proto;
[[deprecated("Remove in v4.1.  Use zeek::id::string_set.")]]
extern TableType* string_set;
[[deprecated("Remove in v4.1.  Use zeek::id::string_array.")]]
extern TableType* string_array;
[[deprecated("Remove in v4.1.  Use zeek::id::count_set.")]]
extern TableType* count_set;
[[deprecated("Remove in v4.1.  Use zeek::id::string_vec.")]]
extern VectorType* string_vec;
[[deprecated("Remove in v4.1.  Use zeek::id::index_vec.")]]
extern VectorType* index_vec;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern VectorType* mime_matches;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* mime_match;

extern int watchdog_interval;

extern int max_timer_expires;

extern int ignore_checksums;
extern int partial_connection_ok;
extern int tcp_SYN_ack_ok;
extern int tcp_match_undelivered;

extern int encap_hdr_size;

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

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* socks_address;

extern double non_analyzed_lifetime;
extern double tcp_inactivity_timeout;
extern double udp_inactivity_timeout;
extern double icmp_inactivity_timeout;

extern int tcp_storm_thresh;
extern double tcp_storm_interarrival_thresh;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableVal* tcp_reassembler_ports_orig;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableVal* tcp_reassembler_ports_resp;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableVal* tcp_content_delivery_ports_orig;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableVal* tcp_content_delivery_ports_resp;
extern bool tcp_content_deliver_all_orig;
extern bool tcp_content_deliver_all_resp;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableVal* udp_content_delivery_ports_orig;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableVal* udp_content_delivery_ports_resp;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableVal* udp_content_ports;
extern bool udp_content_deliver_all_orig;
extern bool udp_content_deliver_all_resp;
extern bool udp_content_delivery_ports_use_resp;

extern double dns_session_timeout;
extern double rpc_timeout;

extern int mime_segment_length;
extern int mime_segment_overlap_length;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* mime_header_rec;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableType* mime_header_list;

extern int http_entity_data_delivery_size;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* http_stats_rec;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* http_message_stat;
extern int truncate_http_URI;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* pm_mapping;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableType* pm_mappings;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* pm_port_request;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* pm_callit_request;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* geo_location;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* entropy_test_result;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* dns_msg;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* dns_answer;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* dns_soa;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* dns_edns_additional;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* dns_tsig_additional;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* dns_rrsig_rr;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* dns_dnskey_rr;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* dns_nsec3_rr;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* dns_ds_rr;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableVal* dns_skip_auth;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableVal* dns_skip_addl;
extern int dns_skip_all_auth;
extern int dns_skip_all_addl;
extern int dns_max_queries;

extern double stp_delta;
extern double stp_idle_min;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableVal* stp_skip_src;

extern double table_expire_interval;
extern double table_expire_delay;
extern int table_incremental_step;

extern int orig_addr_anonymization, resp_addr_anonymization;
extern int other_addr_anonymization;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableVal* preserve_orig_addr;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableVal* preserve_resp_addr;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableVal* preserve_other_addr;

extern double connection_status_update_interval;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* rotate_info;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern StringVal* log_rotate_base_time;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern StringVal* peer_description;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern Val* profiling_file;
extern double profiling_interval;
extern int expensive_profiling_multiple;

extern int segment_profiling;
extern int pkt_profile_mode;
extern double pkt_profile_freq;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern Val* pkt_profile_file;

extern int load_sample_freq;

extern int packet_filter_default;

extern int sig_max_group_size;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableType* irc_join_list;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* irc_join_info;

extern int dpd_reassemble_first_packets;
extern int dpd_buffer_size;
extern int dpd_match_only_beginning;
extern int dpd_late_match_stop;
extern int dpd_ignore_ports;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableVal* likely_server_ports;

extern int check_for_unused_event_handlers;

extern int suppress_local_output;

extern double timer_mgr_inactivity_timeout;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern StringVal* trace_output_file;

extern int record_all_packets;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* script_id;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableType* id_table;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* record_field;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern TableType* record_field_table;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern RecordType* call_argument;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern VectorType* call_argument_vector;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern StringVal* cmd_line_bpf_filter;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern StringVal* global_hash_seed;

extern bro_uint_t bits_per_uid;

// Initializes globals that don't pertain to network/event analysis.
extern void init_general_global_var();

extern void init_event_handlers();
extern void init_net_var();

#include "const.bif.netvar_h"
#include "types.bif.netvar_h"
#include "event.bif.netvar_h"
#include "reporter.bif.netvar_h"
#include "supervisor.bif.netvar_h"
