// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "Var.h"
#include "NetVar.h"

RecordType* conn_id;
RecordType* endpoint;
RecordType* endpoint_stats;
RecordType* connection_type;
RecordType* fa_file_type;
RecordType* fa_metadata_type;
RecordType* icmp_conn;
RecordType* icmp_context;
RecordType* SYN_packet;
RecordType* pcap_packet;
RecordType* raw_pkt_hdr_type;
RecordType* l2_hdr_type;
RecordType* signature_state;
EnumType* transport_proto;
TableType* string_set;
TableType* string_array;
TableType* count_set;
VectorType* string_vec;
VectorType* index_vec;
VectorType* mime_matches;
RecordType* mime_match;

int watchdog_interval;

int max_timer_expires;
int max_remote_events_processed;

int ignore_checksums;
int partial_connection_ok;
int tcp_SYN_ack_ok;
int tcp_match_undelivered;

int encap_hdr_size;

double frag_timeout;

double tcp_SYN_timeout;
double tcp_session_timer;
double tcp_connection_linger;
double tcp_attempt_delay;
double tcp_close_delay;
double tcp_reset_delay;
double tcp_partial_close_delay;

int tcp_max_initial_window;
int tcp_max_above_hole_without_any_acks;
int tcp_excessive_data_without_further_acks;
int tcp_max_old_segments;

RecordType* socks_address;

double non_analyzed_lifetime;
double tcp_inactivity_timeout;
double udp_inactivity_timeout;
double icmp_inactivity_timeout;

int tcp_storm_thresh;
double tcp_storm_interarrival_thresh;

TableVal* tcp_reassembler_ports_orig;
TableVal* tcp_reassembler_ports_resp;

TableVal* tcp_content_delivery_ports_orig;
TableVal* tcp_content_delivery_ports_resp;
bool tcp_content_deliver_all_orig;
bool tcp_content_deliver_all_resp;

TableVal* udp_content_delivery_ports_orig;
TableVal* udp_content_delivery_ports_resp;
bool udp_content_deliver_all_orig;
bool udp_content_deliver_all_resp;

double dns_session_timeout;
double ntp_session_timeout;
double rpc_timeout;

ListVal* skip_authentication;
ListVal* direct_login_prompts;
ListVal* login_prompts;
ListVal* login_non_failure_msgs;
ListVal* login_failure_msgs;
ListVal* login_success_msgs;
ListVal* login_timeouts;

int mime_segment_length;
int mime_segment_overlap_length;
RecordType* mime_header_rec;
TableType* mime_header_list;

int http_entity_data_delivery_size;
RecordType* http_stats_rec;
RecordType* http_message_stat;
int truncate_http_URI;

RecordType* pm_mapping;
TableType* pm_mappings;
RecordType* pm_port_request;
RecordType* pm_callit_request;

RecordType* ntp_msg;

RecordType* geo_location;

RecordType* entropy_test_result;

RecordType* dns_msg;
RecordType* dns_answer;
RecordType* dns_soa;
RecordType* dns_edns_additional;
RecordType* dns_tsig_additional;
RecordType* dns_rrsig_rr;
RecordType* dns_dnskey_rr;
RecordType* dns_nsec3_rr;
RecordType* dns_ds_rr;
TableVal* dns_skip_auth;
TableVal* dns_skip_addl;
int dns_skip_all_auth;
int dns_skip_all_addl;
int dns_max_queries;

double stp_delta;
double stp_idle_min;
TableVal* stp_skip_src;

double interconn_min_interarrival;
double interconn_max_interarrival;
int interconn_max_keystroke_pkt_size;
int interconn_default_pkt_size;
double interconn_stat_period;
double interconn_stat_backoff;
RecordType* interconn_endp_stats;

double backdoor_stat_period;
double backdoor_stat_backoff;

RecordType* backdoor_endp_stats;

RecordType* software;
RecordType* software_version;
RecordType* OS_version;
EnumType* OS_version_inference;
TableVal* generate_OS_version_event;

double table_expire_interval;
double table_expire_delay;
int table_incremental_step;

RecordType* packet_type;

double connection_status_update_interval;

StringVal* state_dir;
double state_write_delay;

int orig_addr_anonymization, resp_addr_anonymization;
int other_addr_anonymization;
TableVal* preserve_orig_addr;
TableVal* preserve_resp_addr;
TableVal* preserve_other_addr;

int max_files_in_cache;
double log_rotate_interval;
double log_max_size;
RecordType* rotate_info;
StringVal* log_encryption_key;
StringVal* log_rotate_base_time;

StringVal* peer_description;
RecordType* peer;
int forward_remote_state_changes;
int forward_remote_events;
int remote_check_sync_consistency;
bro_uint_t chunked_io_buffer_soft_cap;

StringVal* ssl_ca_certificate;
StringVal* ssl_private_key;
StringVal* ssl_passphrase;

Val* profiling_file;
double profiling_interval;
int expensive_profiling_multiple;
int segment_profiling;
int pkt_profile_mode;
double pkt_profile_freq;
Val* pkt_profile_file;

int load_sample_freq;

double gap_report_freq;

int packet_filter_default;

int sig_max_group_size;

int enable_syslog;

TableType* irc_join_list;
RecordType* irc_join_info;
TableVal* irc_servers;

int dpd_reassemble_first_packets;
int dpd_buffer_size;
int dpd_match_only_beginning;
int dpd_ignore_ports;

TableVal* likely_server_ports;

double remote_trace_sync_interval;
int remote_trace_sync_peers;

int check_for_unused_event_handlers;
int dump_used_event_handlers;

int suppress_local_output;

double timer_mgr_inactivity_timeout;

StringVal* trace_output_file;

int record_all_packets;

RecordType* script_id;
TableType* id_table;
RecordType* record_field;
TableType* record_field_table;
RecordType* call_argument;
VectorType* call_argument_vector;

StringVal* cmd_line_bpf_filter;

StringVal* global_hash_seed;

bro_uint_t bits_per_uid;

#include "const.bif.netvar_def"
#include "types.bif.netvar_def"
#include "event.bif.netvar_def"
#include "reporter.bif.netvar_def"

void init_event_handlers()
	{
#include "event.bif.netvar_init"
	}

void init_general_global_var()
	{
	table_expire_interval = opt_internal_double("table_expire_interval");
	table_expire_delay = opt_internal_double("table_expire_delay");
	table_incremental_step = opt_internal_int("table_incremental_step");

	state_dir = internal_val("state_dir")->AsStringVal();
	state_write_delay = opt_internal_double("state_write_delay");

	max_files_in_cache = opt_internal_int("max_files_in_cache");
	log_rotate_interval = opt_internal_double("log_rotate_interval");
	log_max_size = opt_internal_double("log_max_size");
	rotate_info = internal_type("rotate_info")->AsRecordType();
	log_encryption_key = opt_internal_string("log_encryption_key");
	log_rotate_base_time = opt_internal_string("log_rotate_base_time");

	peer_description =
		internal_val("peer_description")->AsStringVal();
	peer = internal_type("event_peer")->AsRecordType();
	forward_remote_state_changes =
		opt_internal_int("forward_remote_state_changes");
	forward_remote_events = opt_internal_int("forward_remote_events");
	remote_check_sync_consistency =
		opt_internal_int("remote_check_sync_consistency");
	chunked_io_buffer_soft_cap = opt_internal_unsigned("chunked_io_buffer_soft_cap");

	ssl_ca_certificate = internal_val("ssl_ca_certificate")->AsStringVal();
	ssl_private_key = internal_val("ssl_private_key")->AsStringVal();
	ssl_passphrase = internal_val("ssl_passphrase")->AsStringVal();

	packet_filter_default = opt_internal_int("packet_filter_default");

	sig_max_group_size = opt_internal_int("sig_max_group_size");
	enable_syslog = opt_internal_int("enable_syslog");

	check_for_unused_event_handlers =
		opt_internal_int("check_for_unused_event_handlers");
	dump_used_event_handlers =
		opt_internal_int("dump_used_event_handlers");

	suppress_local_output = opt_internal_int("suppress_local_output");

	trace_output_file = internal_val("trace_output_file")->AsStringVal();

	record_all_packets = opt_internal_int("record_all_packets");

	cmd_line_bpf_filter =
		internal_val("cmd_line_bpf_filter")->AsStringVal();

	global_hash_seed = opt_internal_string("global_hash_seed");

	bits_per_uid = opt_internal_unsigned("bits_per_uid");
	}

void init_net_var()
	{
#include "const.bif.netvar_init"
#include "types.bif.netvar_init"
#include "reporter.bif.netvar_init"

	conn_id = internal_type("conn_id")->AsRecordType();
	endpoint = internal_type("endpoint")->AsRecordType();
	endpoint_stats = internal_type("endpoint_stats")->AsRecordType();
	connection_type = internal_type("connection")->AsRecordType();
	fa_file_type = internal_type("fa_file")->AsRecordType();
	fa_metadata_type = internal_type("fa_metadata")->AsRecordType();
	icmp_conn = internal_type("icmp_conn")->AsRecordType();
	icmp_context = internal_type("icmp_context")->AsRecordType();
	signature_state = internal_type("signature_state")->AsRecordType();
	SYN_packet = internal_type("SYN_packet")->AsRecordType();
	pcap_packet = internal_type("pcap_packet")->AsRecordType();
	raw_pkt_hdr_type = internal_type("raw_pkt_hdr")->AsRecordType();
	l2_hdr_type = internal_type("l2_hdr")->AsRecordType();
	transport_proto = internal_type("transport_proto")->AsEnumType();
	string_set = internal_type("string_set")->AsTableType();
	string_array = internal_type("string_array")->AsTableType();
	string_vec = internal_type("string_vec")->AsVectorType();
	index_vec = internal_type("index_vec")->AsVectorType();
	mime_match = internal_type("mime_match")->AsRecordType();
	mime_matches = internal_type("mime_matches")->AsVectorType();

	ignore_checksums = opt_internal_int("ignore_checksums");
	partial_connection_ok = opt_internal_int("partial_connection_ok");
	tcp_SYN_ack_ok = opt_internal_int("tcp_SYN_ack_ok");
	tcp_match_undelivered = opt_internal_int("tcp_match_undelivered");

	encap_hdr_size = opt_internal_int("encap_hdr_size");

	frag_timeout = opt_internal_double("frag_timeout");

	tcp_SYN_timeout = opt_internal_double("tcp_SYN_timeout");
	tcp_session_timer = opt_internal_double("tcp_session_timer");
	tcp_connection_linger = opt_internal_double("tcp_connection_linger");
	tcp_attempt_delay = opt_internal_double("tcp_attempt_delay");
	tcp_close_delay = opt_internal_double("tcp_close_delay");
	tcp_reset_delay = opt_internal_double("tcp_reset_delay");
	tcp_partial_close_delay = opt_internal_double("tcp_partial_close_delay");

	tcp_max_initial_window = opt_internal_int("tcp_max_initial_window");
	tcp_max_above_hole_without_any_acks =
		opt_internal_int("tcp_max_above_hole_without_any_acks");
	tcp_excessive_data_without_further_acks =
		opt_internal_int("tcp_excessive_data_without_further_acks");
	tcp_max_old_segments = opt_internal_int("tcp_max_old_segments");

	socks_address = internal_type("SOCKS::Address")->AsRecordType();

	non_analyzed_lifetime = opt_internal_double("non_analyzed_lifetime");
	tcp_inactivity_timeout = opt_internal_double("tcp_inactivity_timeout");
	udp_inactivity_timeout = opt_internal_double("udp_inactivity_timeout");
	icmp_inactivity_timeout = opt_internal_double("icmp_inactivity_timeout");

	tcp_storm_thresh = opt_internal_int("tcp_storm_thresh");
	tcp_storm_interarrival_thresh =
		opt_internal_double("tcp_storm_interarrival_thresh");

	tcp_reassembler_ports_orig =
		internal_val("tcp_reassembler_ports_orig")->AsTableVal();
	tcp_reassembler_ports_resp =
		internal_val("tcp_reassembler_ports_resp")->AsTableVal();

	tcp_content_delivery_ports_orig =
		internal_val("tcp_content_delivery_ports_orig")->AsTableVal();
	tcp_content_delivery_ports_resp =
		internal_val("tcp_content_delivery_ports_resp")->AsTableVal();
	tcp_content_deliver_all_orig =
		bool(internal_val("tcp_content_deliver_all_orig")->AsBool());
	tcp_content_deliver_all_resp =
		bool(internal_val("tcp_content_deliver_all_resp")->AsBool());

	udp_content_delivery_ports_orig =
		internal_val("udp_content_delivery_ports_orig")->AsTableVal();
	udp_content_delivery_ports_resp =
		internal_val("udp_content_delivery_ports_resp")->AsTableVal();
	udp_content_deliver_all_orig =
		bool(internal_val("udp_content_deliver_all_orig")->AsBool());
	udp_content_deliver_all_resp =
		bool(internal_val("udp_content_deliver_all_resp")->AsBool());

	dns_session_timeout = opt_internal_double("dns_session_timeout");
	ntp_session_timeout = opt_internal_double("ntp_session_timeout");
	rpc_timeout = opt_internal_double("rpc_timeout");

	watchdog_interval = int(opt_internal_double("watchdog_interval"));

	max_timer_expires = opt_internal_int("max_timer_expires");
	max_remote_events_processed =
		opt_internal_int("max_remote_events_processed");

	skip_authentication = internal_list_val("skip_authentication");
	direct_login_prompts = internal_list_val("direct_login_prompts");
	login_prompts = internal_list_val("login_prompts");
	login_non_failure_msgs = internal_list_val("login_non_failure_msgs");
	login_failure_msgs = internal_list_val("login_failure_msgs");
	login_success_msgs = internal_list_val("login_success_msgs");
	login_timeouts = internal_list_val("login_timeouts");

	mime_segment_length = opt_internal_int("mime_segment_length");
	mime_segment_overlap_length = opt_internal_int("mime_segment_overlap_length");
	mime_header_rec = internal_type("mime_header_rec")->AsRecordType();
	mime_header_list = internal_type("mime_header_list")->AsTableType();

	http_entity_data_delivery_size = opt_internal_int("http_entity_data_delivery_size");
	http_stats_rec = internal_type("http_stats_rec")->AsRecordType();
	http_message_stat = internal_type("http_message_stat")->AsRecordType();
	truncate_http_URI = opt_internal_int("truncate_http_URI");

	pm_mapping = internal_type("pm_mapping")->AsRecordType();
	pm_mappings = internal_type("pm_mappings")->AsTableType();
	pm_port_request = internal_type("pm_port_request")->AsRecordType();
	pm_callit_request = internal_type("pm_callit_request")->AsRecordType();

	ntp_msg = internal_type("ntp_msg")->AsRecordType();

	geo_location = internal_type("geo_location")->AsRecordType();

	entropy_test_result = internal_type("entropy_test_result")->AsRecordType();

	dns_msg = internal_type("dns_msg")->AsRecordType();
	dns_answer = internal_type("dns_answer")->AsRecordType();
	dns_soa = internal_type("dns_soa")->AsRecordType();
	dns_edns_additional =
		internal_type("dns_edns_additional")->AsRecordType();
	dns_tsig_additional =
		internal_type("dns_tsig_additional")->AsRecordType();
	dns_rrsig_rr = internal_type("dns_rrsig_rr")->AsRecordType();
	dns_dnskey_rr = internal_type("dns_dnskey_rr")->AsRecordType();
	dns_nsec3_rr = internal_type("dns_nsec3_rr")->AsRecordType();
	dns_ds_rr = internal_type("dns_ds_rr")->AsRecordType();
	dns_skip_auth = internal_val("dns_skip_auth")->AsTableVal();
	dns_skip_addl = internal_val("dns_skip_addl")->AsTableVal();
	dns_skip_all_auth = opt_internal_int("dns_skip_all_auth");
	dns_skip_all_addl = opt_internal_int("dns_skip_all_addl");
	dns_max_queries = opt_internal_int("dns_max_queries");

	stp_delta = opt_internal_double("stp_delta");
	stp_idle_min = opt_internal_double("stp_idle_min");
	stp_skip_src = internal_val("stp_skip_src")->AsTableVal();

	interconn_min_interarrival = opt_internal_double("interconn_min_interarrival");
	interconn_max_interarrival = opt_internal_double("interconn_max_interarrival");
	interconn_max_keystroke_pkt_size = opt_internal_int("interconn_max_keystroke_pkt_size");
	interconn_default_pkt_size = opt_internal_int("interconn_default_pkt_size");
	interconn_stat_period = opt_internal_double("interconn_stat_period");
	interconn_stat_backoff = opt_internal_double("interconn_stat_backoff");
	interconn_endp_stats = internal_type("interconn_endp_stats")->AsRecordType();

	backdoor_stat_period = opt_internal_double("backdoor_stat_period");
	backdoor_stat_backoff = opt_internal_double("backdoor_stat_backoff");
	backdoor_endp_stats = internal_type("backdoor_endp_stats")->AsRecordType();

	software = internal_type("software")->AsRecordType();
	software_version = internal_type("software_version")->AsRecordType();
	OS_version = internal_type("OS_version")->AsRecordType();
	OS_version_inference = internal_type("OS_version_inference")->AsEnumType();
	generate_OS_version_event =
		opt_internal_table("generate_OS_version_event");

	packet_type = internal_type("packet")->AsRecordType();

	orig_addr_anonymization = opt_internal_int("orig_addr_anonymization");
	resp_addr_anonymization = opt_internal_int("resp_addr_anonymization");
	other_addr_anonymization = opt_internal_int("other_addr_anonymization");

	preserve_orig_addr = opt_internal_table("preserve_orig_addr");
	preserve_resp_addr = opt_internal_table("preserve_resp_addr");
	preserve_other_addr = opt_internal_table("preserve_other_addr");

	connection_status_update_interval =
		opt_internal_double("connection_status_update_interval");

	profiling_file = internal_val("profiling_file");
	expensive_profiling_multiple =
		opt_internal_int("expensive_profiling_multiple");
	profiling_interval = opt_internal_double("profiling_interval");
	segment_profiling = opt_internal_int("segment_profiling");

	pkt_profile_mode = opt_internal_int("pkt_profile_mode");
	pkt_profile_freq = opt_internal_double("pkt_profile_freq");
	pkt_profile_file = opt_internal_val("pkt_profile_file");

	load_sample_freq = opt_internal_int("load_sample_freq");

	gap_report_freq = opt_internal_double("gap_report_freq");

	irc_join_info = internal_type("irc_join_info")->AsRecordType();
	irc_join_list = internal_type("irc_join_list")->AsTableType();
	irc_servers = internal_val("irc_servers")->AsTableVal();

	remote_trace_sync_interval =
		opt_internal_double("remote_trace_sync_interval");
	remote_trace_sync_peers = opt_internal_int("remote_trace_sync_peers");

	dpd_reassemble_first_packets =
		opt_internal_int("dpd_reassemble_first_packets");
	dpd_buffer_size = opt_internal_int("dpd_buffer_size");
	dpd_match_only_beginning = opt_internal_int("dpd_match_only_beginning");
	dpd_ignore_ports = opt_internal_int("dpd_ignore_ports");

	likely_server_ports = internal_val("likely_server_ports")->AsTableVal();

	timer_mgr_inactivity_timeout =
		opt_internal_double("timer_mgr_inactivity_timeout");

	script_id = internal_type("script_id")->AsRecordType();
	id_table = internal_type("id_table")->AsTableType();
	record_field = internal_type("record_field")->AsRecordType();
	record_field_table = internal_type("record_field_table")->AsTableType();
	call_argument_vector = internal_type("call_argument_vector")->AsVectorType();
	call_argument = internal_type("call_argument")->AsRecordType();
	}
