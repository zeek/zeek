// See the file "COPYING" in the main distribution directory for copyright.

#ifndef netvar_h
#define netvar_h

#include "Val.h"
#include "Func.h"
#include "EventRegistry.h"
#include "Stats.h"

extern RecordType* conn_id;
extern RecordType* endpoint;
extern RecordType* endpoint_stats;
extern RecordType* connection_type;
extern RecordType* fa_file_type;
extern RecordType* icmp_conn;
extern RecordType* icmp_context;
extern RecordType* signature_state;
extern RecordType* SYN_packet;
extern RecordType* pcap_packet;
extern EnumType* transport_proto;
extern TableType* string_set;
extern TableType* string_array;
extern TableType* count_set;
extern VectorType* string_vec;
extern VectorType* mime_matches;
extern RecordType* mime_match;

extern int watchdog_interval;

extern int max_timer_expires;
extern int max_remote_events_processed;

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

extern RecordType* socks_address;

extern double non_analyzed_lifetime;
extern double tcp_inactivity_timeout;
extern double udp_inactivity_timeout;
extern double icmp_inactivity_timeout;

extern int tcp_storm_thresh;
extern double tcp_storm_interarrival_thresh;

extern TableVal* tcp_reassembler_ports_orig;
extern TableVal* tcp_reassembler_ports_resp;

extern TableVal* tcp_content_delivery_ports_orig;
extern TableVal* tcp_content_delivery_ports_resp;
extern bool tcp_content_deliver_all_orig;
extern bool tcp_content_deliver_all_resp;

extern TableVal* udp_content_delivery_ports_orig;
extern TableVal* udp_content_delivery_ports_resp;
extern bool udp_content_deliver_all_orig;
extern bool udp_content_deliver_all_resp;

extern double dns_session_timeout;
extern double ntp_session_timeout;
extern double rpc_timeout;

extern ListVal* skip_authentication;
extern ListVal* direct_login_prompts;
extern ListVal* login_prompts;
extern ListVal* login_non_failure_msgs;
extern ListVal* login_failure_msgs;
extern ListVal* login_success_msgs;
extern ListVal* login_timeouts;

extern int mime_segment_length;
extern int mime_segment_overlap_length;
extern RecordType* mime_header_rec;
extern TableType* mime_header_list;

extern int http_entity_data_delivery_size;
extern RecordType* http_stats_rec;
extern RecordType* http_message_stat;
extern int truncate_http_URI;

extern RecordType* pm_mapping;
extern TableType* pm_mappings;
extern RecordType* pm_port_request;
extern RecordType* pm_callit_request;

extern RecordType* ntp_msg;

extern TableVal* samba_cmds;
extern RecordType* smb_hdr;
extern RecordType* smb_trans;
extern RecordType* smb_trans_data;
extern RecordType* smb_tree_connect;
extern TableType* smb_negotiate;

extern RecordType* geo_location;

extern RecordType* entropy_test_result;

extern TableType* dhcp_router_list;
extern RecordType* dhcp_msg;

extern RecordType* dns_msg;
extern RecordType* dns_answer;
extern RecordType* dns_soa;
extern RecordType* dns_edns_additional;
extern RecordType* dns_tsig_additional;
extern TableVal* dns_skip_auth;
extern TableVal* dns_skip_addl;
extern int dns_skip_all_auth;
extern int dns_skip_all_addl;
extern int dns_max_queries;

extern double stp_delta;
extern double stp_idle_min;
extern TableVal* stp_skip_src;

extern double interconn_min_interarrival;
extern double interconn_max_interarrival;
extern int interconn_max_keystroke_pkt_size;
extern int interconn_default_pkt_size;
extern double interconn_stat_period;
extern double interconn_stat_backoff;
extern RecordType* interconn_endp_stats;

extern double backdoor_stat_period;
extern double backdoor_stat_backoff;

extern RecordType* backdoor_endp_stats;

extern RecordType* software;
extern RecordType* software_version;
extern RecordType* OS_version;
extern EnumType* OS_version_inference;
extern TableVal* generate_OS_version_event;

extern double table_expire_interval;
extern double table_expire_delay;
extern int table_incremental_step;

extern RecordType* packet_type;

extern int orig_addr_anonymization, resp_addr_anonymization;
extern int other_addr_anonymization;
extern TableVal* preserve_orig_addr;
extern TableVal* preserve_resp_addr;
extern TableVal* preserve_other_addr;

extern double connection_status_update_interval;

extern StringVal* state_dir;
extern double state_write_delay;

extern int max_files_in_cache;
extern double log_rotate_interval;
extern double log_max_size;
extern RecordType* rotate_info;
extern StringVal* log_encryption_key;
extern StringVal* log_rotate_base_time;

extern StringVal* peer_description;
extern RecordType* peer;
extern int forward_remote_state_changes;
extern int forward_remote_events;
extern int remote_check_sync_consistency;

extern StringVal* ssl_ca_certificate;
extern StringVal* ssl_private_key;
extern StringVal* ssl_passphrase;

extern Val* profiling_file;
extern double profiling_interval;
extern int expensive_profiling_multiple;

extern int segment_profiling;
extern int pkt_profile_mode;
extern double pkt_profile_freq;
extern Val* pkt_profile_file;

extern int load_sample_freq;

extern double gap_report_freq;
extern RecordType* gap_info;

extern int packet_filter_default;

extern int sig_max_group_size;

extern int enable_syslog;

extern TableType* irc_join_list;
extern RecordType* irc_join_info;
extern TableVal* irc_servers;

extern int dpd_reassemble_first_packets;
extern int dpd_buffer_size;
extern int dpd_match_only_beginning;
extern int dpd_ignore_ports;

extern TableVal* likely_server_ports;

extern double remote_trace_sync_interval;
extern int remote_trace_sync_peers;

extern int check_for_unused_event_handlers;
extern int dump_used_event_handlers;

extern int suppress_local_output;

extern double timer_mgr_inactivity_timeout;

extern int time_machine_profiling;

extern StringVal* trace_output_file;

extern int record_all_packets;

extern RecordType* script_id;
extern TableType* id_table;
extern RecordType* record_field;
extern TableType* record_field_table;
extern RecordType* call_argument;
extern VectorType* call_argument_vector;

extern StringVal* cmd_line_bpf_filter;

extern StringVal* global_hash_seed;

extern bro_uint_t bits_per_uid;

// Initializes globals that don't pertain to network/event analysis.
extern void init_general_global_var();

extern void init_event_handlers();
extern void init_net_var();

#include "const.bif.netvar_h"
#include "types.bif.netvar_h"
#include "event.bif.netvar_h"
#include "logging.bif.netvar_h"
#include "input.bif.netvar_h"
#include "reporter.bif.netvar_h"

#endif
