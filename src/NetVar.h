// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Val.h"
#include "EventRegistry.h"
#include "Stats.h"

namespace zeek {

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

} // namespace zeek

constexpr auto init_general_global_var [[deprecated("Remove in v4.1. Use zeek::init_general_global_var.")]] = zeek::init_general_global_var;
constexpr auto init_event_handlers [[deprecated("Remove in v4.1. Use zeek::init_event_handlers.")]] = zeek::init_event_handlers;
constexpr auto init_net_var [[deprecated("Remove in v4.1. Use zeek::init_net_var.")]] = zeek::init_net_var;

extern int& watchdog_interval [[deprecated("Remove in v4.1. Use zeek::watchdog_interval.")]];
extern int& max_timer_expires [[deprecated("Remove in v4.1. Use zeek::max_timer_expires.")]];
extern int& ignore_checksums [[deprecated("Remove in v4.1. Use zeek::ignore_checksums.")]];
extern int& partial_connection_ok [[deprecated("Remove in v4.1. Use zeek::partial_connection_ok.")]];
extern int& tcp_SYN_ack_ok [[deprecated("Remove in v4.1. Use zeek::tcp_SYN_ack_ok.")]];
extern int& tcp_match_undelivered [[deprecated("Remove in v4.1. Use zeek::tcp_match_undelivered.")]];
extern int& encap_hdr_size [[deprecated("Remove in v4.1. Use zeek::encap_hdr_size.")]];
extern double& frag_timeout [[deprecated("Remove in v4.1. Use zeek::frag_timeout.")]];
extern double& tcp_SYN_timeout [[deprecated("Remove in v4.1. Use zeek::tcp_SYN_timeout.")]];
extern double& tcp_session_timer [[deprecated("Remove in v4.1. Use zeek::tcp_session_timer.")]];
extern double& tcp_connection_linger [[deprecated("Remove in v4.1. Use zeek::tcp_connection_linger.")]];
extern double& tcp_attempt_delay [[deprecated("Remove in v4.1. Use zeek::tcp_attempt_delay.")]];
extern double& tcp_close_delay [[deprecated("Remove in v4.1. Use zeek::tcp_close_delay.")]];
extern double& tcp_partial_close_delay [[deprecated("Remove in v4.1. Use zeek::tcp_partial_close_delay.")]];
extern double& tcp_reset_delay [[deprecated("Remove in v4.1. Use zeek::tcp_reset_delay.")]];
extern int& tcp_max_initial_window [[deprecated("Remove in v4.1. Use zeek::tcp_max_initial_window.")]];
extern int& tcp_max_above_hole_without_any_acks [[deprecated("Remove in v4.1. Use zeek::tcp_max_above_hole_without_any_acks.")]];
extern int& tcp_excessive_data_without_further_acks [[deprecated("Remove in v4.1. Use zeek::tcp_excessive_data_without_further_acks.")]];
extern int& tcp_max_old_segments [[deprecated("Remove in v4.1. Use zeek::tcp_max_old_segments.")]];
extern double& non_analyzed_lifetime [[deprecated("Remove in v4.1. Use zeek::non_analyzed_lifetime.")]];
extern double& tcp_inactivity_timeout [[deprecated("Remove in v4.1. Use zeek::tcp_inactivity_timeout.")]];
extern double& udp_inactivity_timeout [[deprecated("Remove in v4.1. Use zeek::udp_inactivity_timeout.")]];
extern double& icmp_inactivity_timeout [[deprecated("Remove in v4.1. Use zeek::icmp_inactivity_timeout.")]];
extern int& tcp_storm_thresh [[deprecated("Remove in v4.1. Use zeek::tcp_storm_thresh.")]];
extern double& tcp_storm_interarrival_thresh [[deprecated("Remove in v4.1. Use zeek::tcp_storm_interarrival_thresh.")]];
extern bool& tcp_content_deliver_all_orig [[deprecated("Remove in v4.1. Use zeek::tcp_content_deliver_all_orig.")]];
extern bool& tcp_content_deliver_all_resp [[deprecated("Remove in v4.1. Use zeek::tcp_content_deliver_all_resp.")]];
extern bool& udp_content_deliver_all_orig [[deprecated("Remove in v4.1. Use zeek::udp_content_deliver_all_orig.")]];
extern bool& udp_content_deliver_all_resp [[deprecated("Remove in v4.1. Use zeek::udp_content_deliver_all_resp.")]];
extern bool& udp_content_delivery_ports_use_resp [[deprecated("Remove in v4.1. Use zeek::udp_content_delivery_ports_use_resp.")]];
extern double& dns_session_timeout [[deprecated("Remove in v4.1. Use zeek::dns_session_timeout.")]];
extern double& rpc_timeout [[deprecated("Remove in v4.1. Use zeek::rpc_timeout.")]];
extern int& mime_segment_length [[deprecated("Remove in v4.1. Use zeek::mime_segment_length.")]];
extern int& mime_segment_overlap_length [[deprecated("Remove in v4.1. Use zeek::mime_segment_overlap_length.")]];
extern int& http_entity_data_delivery_size [[deprecated("Remove in v4.1. Use zeek::http_entity_data_delivery_size.")]];
extern int& truncate_http_URI [[deprecated("Remove in v4.1. Use zeek::truncate_http_URI.")]];
extern int& dns_skip_all_auth [[deprecated("Remove in v4.1. Use zeek::dns_skip_all_auth.")]];
extern int& dns_skip_all_addl [[deprecated("Remove in v4.1. Use zeek::dns_skip_all_addl.")]];
extern int& dns_max_queries [[deprecated("Remove in v4.1. Use zeek::dns_max_queries.")]];
extern double& stp_delta [[deprecated("Remove in v4.1. Use zeek::stp_delta.")]];
extern double& stp_idle_min [[deprecated("Remove in v4.1. Use zeek::stp_idle_min.")]];
extern double& table_expire_interval [[deprecated("Remove in v4.1. Use zeek::table_expire_interval.")]];
extern double& table_expire_delay [[deprecated("Remove in v4.1. Use zeek::table_expire_delay.")]];
extern int& table_incremental_step [[deprecated("Remove in v4.1. Use zeek::table_incremental_step.")]];
extern int& orig_addr_anonymization [[deprecated("Remove in v4.1. Use zeek::orig_addr_anonymization.")]];
extern int& resp_addr_anonymization [[deprecated("Remove in v4.1. Use zeek::resp_addr_anonymization.")]];
extern int& other_addr_anonymization [[deprecated("Remove in v4.1. Use zeek::other_addr_anonymization.")]];
extern double& connection_status_update_interval [[deprecated("Remove in v4.1. Use zeek::connection_status_update_interval.")]];
extern double& profiling_interval [[deprecated("Remove in v4.1. Use zeek::profiling_interval.")]];
extern int& expensive_profiling_multiple [[deprecated("Remove in v4.1. Use zeek::expensive_profiling_multiple.")]];
extern int& segment_profiling [[deprecated("Remove in v4.1. Use zeek::segment_profiling.")]];
extern int& pkt_profile_mode [[deprecated("Remove in v4.1. Use zeek::pkt_profile_mode.")]];
extern double& pkt_profile_freq [[deprecated("Remove in v4.1. Use zeek::pkt_profile_freq.")]];
extern int& load_sample_freq [[deprecated("Remove in v4.1. Use zeek::load_sample_freq.")]];
extern int& packet_filter_default [[deprecated("Remove in v4.1. Use zeek::packet_filter_default.")]];
extern int& sig_max_group_size [[deprecated("Remove in v4.1. Use zeek::sig_max_group_size.")]];
extern int& dpd_reassemble_first_packets [[deprecated("Remove in v4.1. Use zeek::dpd_reassemble_first_packets.")]];
extern int& dpd_buffer_size [[deprecated("Remove in v4.1. Use zeek::dpd_buffer_size.")]];
extern int& dpd_match_only_beginning [[deprecated("Remove in v4.1. Use zeek::dpd_match_only_beginning.")]];
extern int& dpd_late_match_stop [[deprecated("Remove in v4.1. Use zeek::dpd_late_match_stop.")]];
extern int& dpd_ignore_ports [[deprecated("Remove in v4.1. Use zeek::dpd_ignore_ports.")]];
extern int& check_for_unused_event_handlers [[deprecated("Remove in v4.1. Use zeek::check_for_unused_event_handlers.")]];
extern double& timer_mgr_inactivity_timeout [[deprecated("Remove in v4.1. Use zeek::timer_mgr_inactivity_timeout.")]];
extern int& record_all_packets [[deprecated("Remove in v4.1. Use zeek::record_all_packets.")]];
extern bro_uint_t& bits_per_uid [[deprecated("Remove in v4.1. Use zeek::bits_per_uid.")]];


[[deprecated("Remove in v4.1.  Use zeek::id::conn_id.")]]
extern zeek::RecordType* conn_id;
[[deprecated("Remove in v4.1.  Use zeek::id::endpoint.")]]
extern zeek::RecordType* endpoint;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* endpoint_stats;
[[deprecated("Remove in v4.1.  Use zeek::id::connection.")]]
extern zeek::RecordType* connection_type;
[[deprecated("Remove in v4.1.  Use zeek::id::fa_file.")]]
extern zeek::RecordType* fa_file_type;
[[deprecated("Remove in v4.1.  Use zeek::id::fa_metadata.")]]
extern zeek::RecordType* fa_metadata_type;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* icmp_conn;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* icmp_context;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* signature_state;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* SYN_packet;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* pcap_packet;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* raw_pkt_hdr_type;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* l2_hdr_type;
[[deprecated("Remove in v4.1.  Use zeek::id::transport_proto.")]]
extern zeek::EnumType* transport_proto;
[[deprecated("Remove in v4.1.  Use zeek::id::string_set.")]]
extern zeek::TableType* string_set;
[[deprecated("Remove in v4.1.  Use zeek::id::string_array.")]]
extern zeek::TableType* string_array;
[[deprecated("Remove in v4.1.  Use zeek::id::count_set.")]]
extern zeek::TableType* count_set;
[[deprecated("Remove in v4.1.  Use zeek::id::string_vec.")]]
extern zeek::VectorType* string_vec;
[[deprecated("Remove in v4.1.  Use zeek::id::index_vec.")]]
extern zeek::VectorType* index_vec;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::VectorType* mime_matches;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* mime_match;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* socks_address;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableVal* tcp_reassembler_ports_orig;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableVal* tcp_reassembler_ports_resp;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableVal* tcp_content_delivery_ports_orig;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableVal* tcp_content_delivery_ports_resp;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableVal* udp_content_delivery_ports_orig;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableVal* udp_content_delivery_ports_resp;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableVal* udp_content_ports;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* mime_header_rec;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableType* mime_header_list;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* http_stats_rec;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* http_message_stat;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* pm_mapping;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableType* pm_mappings;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* pm_port_request;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* pm_callit_request;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* geo_location;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* entropy_test_result;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* dns_msg;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* dns_answer;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* dns_soa;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* dns_edns_additional;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* dns_edns_ecs;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* dns_tsig_additional;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* dns_rrsig_rr;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* dns_dnskey_rr;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* dns_nsec3_rr;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* dns_ds_rr;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableVal* dns_skip_auth;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableVal* dns_skip_addl;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableVal* stp_skip_src;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableVal* preserve_orig_addr;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableVal* preserve_resp_addr;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableVal* preserve_other_addr;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* rotate_info;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::StringVal* log_rotate_base_time;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::StringVal* peer_description;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::Val* profiling_file;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::Val* pkt_profile_file;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableType* irc_join_list;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* irc_join_info;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableVal* likely_server_ports;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::StringVal* trace_output_file;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* script_id;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableType* id_table;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* record_field;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::TableType* record_field_table;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::RecordType* call_argument;
[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::VectorType* call_argument_vector;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::StringVal* cmd_line_bpf_filter;

[[deprecated("Remove in v4.1.  Perform your own lookup.")]]
extern zeek::StringVal* global_hash_seed;

#include "const.bif.netvar_h"
#include "types.bif.netvar_h"
#include "event.bif.netvar_h"
#include "reporter.bif.netvar_h"
#include "supervisor.bif.netvar_h"
