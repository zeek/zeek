// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "zeek/NetVar.h"
#include "zeek/Var.h"
#include "zeek/EventHandler.h"
#include "zeek/Val.h"
#include "zeek/ID.h"

zeek::RecordType* conn_id;
zeek::RecordType* endpoint;
zeek::RecordType* endpoint_stats;
zeek::RecordType* connection_type;
zeek::RecordType* fa_file_type;
zeek::RecordType* fa_metadata_type;
zeek::RecordType* icmp_conn;
zeek::RecordType* icmp_context;
zeek::RecordType* SYN_packet;
zeek::RecordType* pcap_packet;
zeek::RecordType* raw_pkt_hdr_type;
zeek::RecordType* l2_hdr_type;
zeek::RecordType* signature_state;
zeek::EnumType* transport_proto;
zeek::TableType* string_set;
zeek::TableType* string_array;
zeek::TableType* count_set;
zeek::VectorType* string_vec;
zeek::VectorType* index_vec;
zeek::VectorType* mime_matches;
zeek::RecordType* mime_match;

zeek::RecordType* socks_address;

zeek::TableVal* tcp_reassembler_ports_orig;
zeek::TableVal* tcp_reassembler_ports_resp;

zeek::TableVal* tcp_content_delivery_ports_orig;
zeek::TableVal* tcp_content_delivery_ports_resp;

zeek::TableVal* udp_content_delivery_ports_orig;
zeek::TableVal* udp_content_delivery_ports_resp;
zeek::TableVal* udp_content_ports;

zeek::RecordType* mime_header_rec;
zeek::TableType* mime_header_list;

zeek::RecordType* http_stats_rec;
zeek::RecordType* http_message_stat;

zeek::RecordType* pm_mapping;
zeek::TableType* pm_mappings;
zeek::RecordType* pm_port_request;
zeek::RecordType* pm_callit_request;

zeek::RecordType* geo_location;

zeek::RecordType* entropy_test_result;

zeek::RecordType* dns_msg;
zeek::RecordType* dns_answer;
zeek::RecordType* dns_soa;
zeek::RecordType* dns_edns_additional;
zeek::RecordType* dns_edns_ecs;
zeek::RecordType* dns_tsig_additional;
zeek::RecordType* dns_rrsig_rr;
zeek::RecordType* dns_dnskey_rr;
zeek::RecordType* dns_nsec3_rr;
zeek::RecordType* dns_nsec3param_rr;
zeek::RecordType* dns_ds_rr;
zeek::RecordType* dns_binds_rr;
zeek::RecordType* dns_loc_rr;
zeek::TableVal* dns_skip_auth;
zeek::TableVal* dns_skip_addl;

zeek::TableVal* stp_skip_src;

zeek::TableVal* preserve_orig_addr;
zeek::TableVal* preserve_resp_addr;
zeek::TableVal* preserve_other_addr;

zeek::RecordType* rotate_info;
zeek::StringVal* log_rotate_base_time;

zeek::StringVal* peer_description;

zeek::Val* profiling_file;
zeek::Val* pkt_profile_file;

zeek::TableType* irc_join_list;
zeek::RecordType* irc_join_info;

zeek::TableVal* likely_server_ports;

zeek::StringVal* trace_output_file;

zeek::RecordType* script_id;
zeek::TableType* id_table;
zeek::RecordType* record_field;
zeek::TableType* record_field_table;
zeek::RecordType* call_argument;
zeek::VectorType* call_argument_vector;

zeek::StringVal* cmd_line_bpf_filter;

zeek::StringVal* global_hash_seed;

namespace zeek::detail {

int watchdog_interval;

int max_timer_expires;

int ignore_checksums;
int partial_connection_ok;
int tcp_SYN_ack_ok;
int tcp_match_undelivered;

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

double non_analyzed_lifetime;
double tcp_inactivity_timeout;
double udp_inactivity_timeout;
double icmp_inactivity_timeout;

int tcp_storm_thresh;
double tcp_storm_interarrival_thresh;

bool tcp_content_deliver_all_orig;
bool tcp_content_deliver_all_resp;
bool udp_content_deliver_all_orig;
bool udp_content_deliver_all_resp;
bool udp_content_delivery_ports_use_resp;

double dns_session_timeout;
double rpc_timeout;

int mime_segment_length;
int mime_segment_overlap_length;
int http_entity_data_delivery_size;
int truncate_http_URI;

int dns_skip_all_auth;
int dns_skip_all_addl;
int dns_max_queries;

double stp_delta;
double stp_idle_min;

double table_expire_interval;
double table_expire_delay;
int table_incremental_step;

double connection_status_update_interval;

int orig_addr_anonymization, resp_addr_anonymization;
int other_addr_anonymization;

double profiling_interval;
int expensive_profiling_multiple;
int segment_profiling;
int pkt_profile_mode;
double pkt_profile_freq;

int load_sample_freq;

int packet_filter_default;

int sig_max_group_size;

int dpd_reassemble_first_packets;
int dpd_buffer_size;
int dpd_match_only_beginning;
int dpd_late_match_stop;
int dpd_ignore_ports;

int check_for_unused_event_handlers;

double timer_mgr_inactivity_timeout;

int record_all_packets;

bro_uint_t bits_per_uid;

} // namespace zeek::detail. The namespace has be closed here before we include the netvar_def files.

// Because of how the BIF include files are built with namespaces already in them,
// these files need to be included separately before the namespace is opened below.

static void bif_init_event_handlers()
	{
#include "event.bif.netvar_init"
	}

static void bif_init_net_var()
	{
#include "const.bif.netvar_init"
#include "reporter.bif.netvar_init"
#include "supervisor.bif.netvar_init"
#include "packet_analysis.bif.netvar_init"
	}

static void init_bif_types()
	{
#include "types.bif.netvar_init"
	}

#include "const.bif.netvar_def"
#include "types.bif.netvar_def"
#include "event.bif.netvar_def"
#include "reporter.bif.netvar_def"
#include "supervisor.bif.netvar_def"
#include "packet_analysis.bif.netvar_def"

// Re-open the namespace now that the bif headers are all included.
namespace zeek::detail {

void init_event_handlers()
	{
	bif_init_event_handlers();
	}

void init_general_global_var()
	{
	table_expire_interval = id::find_val("table_expire_interval")->AsInterval();
	table_expire_delay = id::find_val("table_expire_delay")->AsInterval();
	table_incremental_step = id::find_val("table_incremental_step")->AsCount();
	packet_filter_default = id::find_val("packet_filter_default")->AsBool();
	sig_max_group_size = id::find_val("sig_max_group_size")->AsCount();
	check_for_unused_event_handlers = id::find_val("check_for_unused_event_handlers")->AsBool();
	record_all_packets = id::find_val("record_all_packets")->AsBool();
	bits_per_uid = id::find_val("bits_per_uid")->AsCount();
	}

void init_builtin_types()
	{
	init_bif_types();
	id::detail::init_types();
	}

void init_net_var()
	{
	bif_init_net_var();

	ignore_checksums = id::find_val("ignore_checksums")->AsBool();
	partial_connection_ok = id::find_val("partial_connection_ok")->AsBool();
	tcp_SYN_ack_ok = id::find_val("tcp_SYN_ack_ok")->AsBool();
	tcp_match_undelivered = id::find_val("tcp_match_undelivered")->AsBool();

	frag_timeout = id::find_val("frag_timeout")->AsInterval();

	tcp_SYN_timeout = id::find_val("tcp_SYN_timeout")->AsInterval();
	tcp_session_timer = id::find_val("tcp_session_timer")->AsInterval();
	tcp_connection_linger = id::find_val("tcp_connection_linger")->AsInterval();
	tcp_attempt_delay = id::find_val("tcp_attempt_delay")->AsInterval();
	tcp_close_delay = id::find_val("tcp_close_delay")->AsInterval();
	tcp_reset_delay = id::find_val("tcp_reset_delay")->AsInterval();
	tcp_partial_close_delay = id::find_val("tcp_partial_close_delay")->AsInterval();

	tcp_max_initial_window = id::find_val("tcp_max_initial_window")->AsCount();
	tcp_max_above_hole_without_any_acks = id::find_val("tcp_max_above_hole_without_any_acks")->AsCount();
	tcp_excessive_data_without_further_acks = id::find_val("tcp_excessive_data_without_further_acks")->AsCount();
	tcp_max_old_segments = id::find_val("tcp_max_old_segments")->AsCount();

	non_analyzed_lifetime = id::find_val("non_analyzed_lifetime")->AsInterval();
	tcp_inactivity_timeout = id::find_val("tcp_inactivity_timeout")->AsInterval();
	udp_inactivity_timeout = id::find_val("udp_inactivity_timeout")->AsInterval();
	icmp_inactivity_timeout = id::find_val("icmp_inactivity_timeout")->AsInterval();

	tcp_storm_thresh = id::find_val("tcp_storm_thresh")->AsCount();
	tcp_storm_interarrival_thresh = id::find_val("tcp_storm_interarrival_thresh")->AsInterval();

	tcp_content_deliver_all_orig =
		bool(id::find_val("tcp_content_deliver_all_orig")->AsBool());
	tcp_content_deliver_all_resp =
		bool(id::find_val("tcp_content_deliver_all_resp")->AsBool());

	udp_content_deliver_all_orig =
		bool(id::find_val("udp_content_deliver_all_orig")->AsBool());
	udp_content_deliver_all_resp =
		bool(id::find_val("udp_content_deliver_all_resp")->AsBool());
	udp_content_delivery_ports_use_resp =
		bool(id::find_val("udp_content_delivery_ports_use_resp")->AsBool());

	dns_session_timeout = id::find_val("dns_session_timeout")->AsInterval();
	rpc_timeout = id::find_val("rpc_timeout")->AsInterval();

	watchdog_interval = int(id::find_val("watchdog_interval")->AsInterval());

	max_timer_expires = id::find_val("max_timer_expires")->AsCount();

	mime_segment_length = id::find_val("mime_segment_length")->AsCount();
	mime_segment_overlap_length = id::find_val("mime_segment_overlap_length")->AsCount();

	http_entity_data_delivery_size = id::find_val("http_entity_data_delivery_size")->AsCount();
	truncate_http_URI = id::find_val("truncate_http_URI")->AsInt();

	dns_skip_all_auth = id::find_val("dns_skip_all_auth")->AsBool();
	dns_skip_all_addl = id::find_val("dns_skip_all_addl")->AsBool();
	dns_max_queries = id::find_val("dns_max_queries")->AsCount();

	stp_delta = 0.0;
	if ( const auto& v = id::find_val("stp_delta") ) stp_delta = v->AsInterval();
	stp_idle_min = 0.0;
	if ( const auto& v = id::find_val("stp_idle_min") ) stp_delta = v->AsInterval();

	orig_addr_anonymization = 0;
	if ( const auto& id = id::find("orig_addr_anonymization") )
		if ( const auto& v = id->GetVal() )
			orig_addr_anonymization = v->AsInt();
	resp_addr_anonymization = 0;
	if ( const auto& id = id::find("resp_addr_anonymization") )
		if ( const auto& v = id->GetVal() )
			resp_addr_anonymization = v->AsInt();
	other_addr_anonymization = 0;
	if ( const auto& id = id::find("other_addr_anonymization") )
		if ( const auto& v = id->GetVal() )
			other_addr_anonymization = v->AsInt();

	connection_status_update_interval = 0.0;
	if ( const auto& id = id::find("connection_status_update_interval") )
		if ( const auto& v = id->GetVal() )
			connection_status_update_interval = v->AsInterval();

	expensive_profiling_multiple = id::find_val("expensive_profiling_multiple")->AsCount();
	profiling_interval = id::find_val("profiling_interval")->AsInterval();
	segment_profiling = id::find_val("segment_profiling")->AsBool();

	pkt_profile_mode = id::find_val("pkt_profile_mode")->InternalInt();
	pkt_profile_freq = id::find_val("pkt_profile_freq")->AsDouble();

	load_sample_freq = id::find_val("load_sample_freq")->AsCount();

	dpd_reassemble_first_packets = id::find_val("dpd_reassemble_first_packets")->AsBool();
	dpd_buffer_size = id::find_val("dpd_buffer_size")->AsCount();
	dpd_match_only_beginning = id::find_val("dpd_match_only_beginning")->AsBool();
	dpd_late_match_stop = id::find_val("dpd_late_match_stop")->AsBool();
	dpd_ignore_ports = id::find_val("dpd_ignore_ports")->AsBool();

	timer_mgr_inactivity_timeout = id::find_val("timer_mgr_inactivity_timeout")->AsInterval();
	}

} // namespace zeek::detail
