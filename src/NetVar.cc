// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "NetVar.h"
#include "Var.h"
#include "EventHandler.h"
#include "Val.h"
#include "ID.h"

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
	table_expire_interval = zeek::id::lookup_val("table_expire_interval")->AsInterval();
	table_expire_delay = zeek::id::lookup_val("table_expire_delay")->AsInterval();
	table_incremental_step = zeek::id::lookup_val("table_incremental_step")->AsCount();
	packet_filter_default = zeek::id::lookup_val("packet_filter_default")->AsBool();
	sig_max_group_size = zeek::id::lookup_val("sig_max_group_size")->AsCount();
	check_for_unused_event_handlers = zeek::id::lookup_val("check_for_unused_event_handlers")->AsBool();
	record_all_packets = zeek::id::lookup_val("record_all_packets")->AsBool();
	bits_per_uid = zeek::id::lookup_val("bits_per_uid")->AsCount();
	}

extern void zeek_legacy_netvar_init();

void init_net_var()
	{
#include "const.bif.netvar_init"
#include "types.bif.netvar_init"
#include "reporter.bif.netvar_init"
#include "supervisor.bif.netvar_init"

	zeek::id::detail::init();
	zeek_legacy_netvar_init();

	ignore_checksums = zeek::id::lookup_val("ignore_checksums")->AsBool();
	partial_connection_ok = zeek::id::lookup_val("partial_connection_ok")->AsBool();
	tcp_SYN_ack_ok = zeek::id::lookup_val("tcp_SYN_ack_ok")->AsBool();
	tcp_match_undelivered = zeek::id::lookup_val("tcp_match_undelivered")->AsBool();

	encap_hdr_size = zeek::id::lookup_val("encap_hdr_size")->AsCount();

	frag_timeout = zeek::id::lookup_val("frag_timeout")->AsInterval();

	tcp_SYN_timeout = zeek::id::lookup_val("tcp_SYN_timeout")->AsInterval();
	tcp_session_timer = zeek::id::lookup_val("tcp_session_timer")->AsInterval();
	tcp_connection_linger = zeek::id::lookup_val("tcp_connection_linger")->AsInterval();
	tcp_attempt_delay = zeek::id::lookup_val("tcp_attempt_delay")->AsInterval();
	tcp_close_delay = zeek::id::lookup_val("tcp_close_delay")->AsInterval();
	tcp_reset_delay = zeek::id::lookup_val("tcp_reset_delay")->AsInterval();
	tcp_partial_close_delay = zeek::id::lookup_val("tcp_partial_close_delay")->AsInterval();

	tcp_max_initial_window = zeek::id::lookup_val("tcp_max_initial_window")->AsCount();
	tcp_max_above_hole_without_any_acks = zeek::id::lookup_val("tcp_max_above_hole_without_any_acks")->AsCount();
	tcp_excessive_data_without_further_acks = zeek::id::lookup_val("tcp_excessive_data_without_further_acks")->AsCount();
	tcp_max_old_segments = zeek::id::lookup_val("tcp_max_old_segments")->AsCount();

	non_analyzed_lifetime = zeek::id::lookup_val("non_analyzed_lifetime")->AsInterval();
	tcp_inactivity_timeout = zeek::id::lookup_val("tcp_inactivity_timeout")->AsInterval();
	udp_inactivity_timeout = zeek::id::lookup_val("udp_inactivity_timeout")->AsInterval();
	icmp_inactivity_timeout = zeek::id::lookup_val("icmp_inactivity_timeout")->AsInterval();

	tcp_storm_thresh = zeek::id::lookup_val("tcp_storm_thresh")->AsCount();
	tcp_storm_interarrival_thresh = zeek::id::lookup_val("tcp_storm_interarrival_thresh")->AsInterval();

	tcp_content_deliver_all_orig =
		bool(zeek::id::lookup_val("tcp_content_deliver_all_orig")->AsBool());
	tcp_content_deliver_all_resp =
		bool(zeek::id::lookup_val("tcp_content_deliver_all_resp")->AsBool());

	udp_content_deliver_all_orig =
		bool(zeek::id::lookup_val("udp_content_deliver_all_orig")->AsBool());
	udp_content_deliver_all_resp =
		bool(zeek::id::lookup_val("udp_content_deliver_all_resp")->AsBool());
	udp_content_delivery_ports_use_resp =
		bool(zeek::id::lookup_val("udp_content_delivery_ports_use_resp")->AsBool());

	dns_session_timeout = zeek::id::lookup_val("dns_session_timeout")->AsInterval();
	rpc_timeout = zeek::id::lookup_val("rpc_timeout")->AsInterval();

	watchdog_interval = int(zeek::id::lookup_val("watchdog_interval")->AsInterval());

	max_timer_expires = zeek::id::lookup_val("max_timer_expires")->AsCount();

	mime_segment_length = zeek::id::lookup_val("mime_segment_length")->AsCount();
	mime_segment_overlap_length = zeek::id::lookup_val("mime_segment_overlap_length")->AsCount();

	http_entity_data_delivery_size = zeek::id::lookup_val("http_entity_data_delivery_size")->AsCount();
	truncate_http_URI = zeek::id::lookup_val("truncate_http_URI")->AsInt();

	dns_skip_all_auth = zeek::id::lookup_val("dns_skip_all_auth")->AsBool();
	dns_skip_all_addl = zeek::id::lookup_val("dns_skip_all_addl")->AsBool();
	dns_max_queries = zeek::id::lookup_val("dns_max_queries")->AsCount();

	stp_delta = 0.0;
	if ( const auto& v = zeek::id::lookup_val("stp_delta") ) stp_delta = v->AsInterval();
	stp_idle_min = 0.0;
	if ( const auto& v = zeek::id::lookup_val("stp_idle_min") ) stp_delta = v->AsInterval();

	orig_addr_anonymization = 0;
	if ( const auto& id = zeek::id::lookup("orig_addr_anonymization") )
		if ( const auto& v = id->GetVal() )
			orig_addr_anonymization = v->AsInt();
	resp_addr_anonymization = 0;
	if ( const auto& id = zeek::id::lookup("resp_addr_anonymization") )
		if ( const auto& v = id->GetVal() )
			resp_addr_anonymization = v->AsInt();
	other_addr_anonymization = 0;
	if ( const auto& id = zeek::id::lookup("other_addr_anonymization") )
		if ( const auto& v = id->GetVal() )
			other_addr_anonymization = v->AsInt();

	connection_status_update_interval = 0.0;
	if ( const auto& id = zeek::id::lookup("connection_status_update_interval") )
		if ( const auto& v = id->GetVal() )
			connection_status_update_interval = v->AsInterval();

	expensive_profiling_multiple = zeek::id::lookup_val("expensive_profiling_multiple")->AsCount();
	profiling_interval = zeek::id::lookup_val("profiling_interval")->AsInterval();
	segment_profiling = zeek::id::lookup_val("segment_profiling")->AsBool();

	pkt_profile_mode = zeek::id::lookup_val("pkt_profile_mode")->InternalInt();
	pkt_profile_freq = zeek::id::lookup_val("pkt_profile_freq")->AsDouble();

	load_sample_freq = zeek::id::lookup_val("load_sample_freq")->AsCount();

	dpd_reassemble_first_packets = zeek::id::lookup_val("dpd_reassemble_first_packets")->AsBool();
	dpd_buffer_size = zeek::id::lookup_val("dpd_buffer_size")->AsCount();
	dpd_match_only_beginning = zeek::id::lookup_val("dpd_match_only_beginning")->AsBool();
	dpd_late_match_stop = zeek::id::lookup_val("dpd_late_match_stop")->AsBool();
	dpd_ignore_ports = zeek::id::lookup_val("dpd_ignore_ports")->AsBool();

	timer_mgr_inactivity_timeout = zeek::id::lookup_val("timer_mgr_inactivity_timeout")->AsInterval();
	}
