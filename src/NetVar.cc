// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "NetVar.h"
#include "Var.h"
#include "EventHandler.h"
#include "Val.h"

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
TableVal* udp_content_ports;
bool udp_content_deliver_all_orig;
bool udp_content_deliver_all_resp;
bool udp_content_delivery_ports_use_resp;

double dns_session_timeout;
double rpc_timeout;

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

double table_expire_interval;
double table_expire_delay;
int table_incremental_step;

double connection_status_update_interval;

int orig_addr_anonymization, resp_addr_anonymization;
int other_addr_anonymization;
TableVal* preserve_orig_addr;
TableVal* preserve_resp_addr;
TableVal* preserve_other_addr;

RecordType* rotate_info;
StringVal* log_rotate_base_time;

StringVal* peer_description;

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

TableType* irc_join_list;
RecordType* irc_join_info;

int dpd_reassemble_first_packets;
int dpd_buffer_size;
int dpd_match_only_beginning;
int dpd_late_match_stop;
int dpd_ignore_ports;

TableVal* likely_server_ports;

int check_for_unused_event_handlers;

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
#include "supervisor.bif.netvar_def"

void init_event_handlers()
	{
#include "event.bif.netvar_init"
	}

void init_general_global_var()
	{
	table_expire_interval = opt_internal_double("table_expire_interval");
	table_expire_delay = opt_internal_double("table_expire_delay");
	table_incremental_step = opt_internal_int("table_incremental_step");

	packet_filter_default = opt_internal_int("packet_filter_default");

	sig_max_group_size = opt_internal_int("sig_max_group_size");

	check_for_unused_event_handlers =
		opt_internal_int("check_for_unused_event_handlers");

	suppress_local_output = opt_internal_int("suppress_local_output");

	record_all_packets = opt_internal_int("record_all_packets");

	bits_per_uid = opt_internal_unsigned("bits_per_uid");
	}

void init_net_var()
	{
#include "const.bif.netvar_init"
#include "types.bif.netvar_init"
#include "reporter.bif.netvar_init"
#include "supervisor.bif.netvar_init"

	zeek::vars::detail::Init();

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

	non_analyzed_lifetime = opt_internal_double("non_analyzed_lifetime");
	tcp_inactivity_timeout = opt_internal_double("tcp_inactivity_timeout");
	udp_inactivity_timeout = opt_internal_double("udp_inactivity_timeout");
	icmp_inactivity_timeout = opt_internal_double("icmp_inactivity_timeout");

	tcp_storm_thresh = opt_internal_int("tcp_storm_thresh");
	tcp_storm_interarrival_thresh =
		opt_internal_double("tcp_storm_interarrival_thresh");

	tcp_content_deliver_all_orig =
		bool(zeek::lookup_val("tcp_content_deliver_all_orig")->AsBool());
	tcp_content_deliver_all_resp =
		bool(zeek::lookup_val("tcp_content_deliver_all_resp")->AsBool());

	udp_content_deliver_all_orig =
		bool(zeek::lookup_val("udp_content_deliver_all_orig")->AsBool());
	udp_content_deliver_all_resp =
		bool(zeek::lookup_val("udp_content_deliver_all_resp")->AsBool());
	udp_content_delivery_ports_use_resp =
		bool(zeek::lookup_val("udp_content_delivery_ports_use_resp")->AsBool());

	dns_session_timeout = opt_internal_double("dns_session_timeout");
	rpc_timeout = opt_internal_double("rpc_timeout");

	watchdog_interval = int(opt_internal_double("watchdog_interval"));

	max_timer_expires = opt_internal_int("max_timer_expires");

	mime_segment_length = opt_internal_int("mime_segment_length");
	mime_segment_overlap_length = opt_internal_int("mime_segment_overlap_length");

	http_entity_data_delivery_size = opt_internal_int("http_entity_data_delivery_size");
	truncate_http_URI = opt_internal_int("truncate_http_URI");

	dns_skip_all_auth = opt_internal_int("dns_skip_all_auth");
	dns_skip_all_addl = opt_internal_int("dns_skip_all_addl");
	dns_max_queries = opt_internal_int("dns_max_queries");

	stp_delta = opt_internal_double("stp_delta");
	stp_idle_min = opt_internal_double("stp_idle_min");

	orig_addr_anonymization = opt_internal_int("orig_addr_anonymization");
	resp_addr_anonymization = opt_internal_int("resp_addr_anonymization");
	other_addr_anonymization = opt_internal_int("other_addr_anonymization");

	connection_status_update_interval =
		opt_internal_double("connection_status_update_interval");

	expensive_profiling_multiple =
		opt_internal_int("expensive_profiling_multiple");
	profiling_interval = opt_internal_double("profiling_interval");
	segment_profiling = opt_internal_int("segment_profiling");

	pkt_profile_mode = opt_internal_int("pkt_profile_mode");
	pkt_profile_freq = opt_internal_double("pkt_profile_freq");

	load_sample_freq = opt_internal_int("load_sample_freq");

	gap_report_freq = opt_internal_double("gap_report_freq");

	dpd_reassemble_first_packets =
		opt_internal_int("dpd_reassemble_first_packets");
	dpd_buffer_size = opt_internal_int("dpd_buffer_size");
	dpd_match_only_beginning = opt_internal_int("dpd_match_only_beginning");
	dpd_late_match_stop = opt_internal_int("dpd_late_match_stop");
	dpd_ignore_ports = opt_internal_int("dpd_ignore_ports");

	timer_mgr_inactivity_timeout =
		opt_internal_double("timer_mgr_inactivity_timeout");
	}
