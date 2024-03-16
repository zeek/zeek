// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/FuncInfo.h"

#include <unordered_set>

namespace zeek::detail {

// See script_opt/ZAM/maint/README for maintenance of the attributes
// in this file.

// Attributes associated with functions. Currently these are mutually
// exclusive (i.e., no function will have more than one), but for now
// we use a bitmask-style approach so we can accommodate future attributes
// that might overlap.

// BiF Functions that are not listed are assumed to have Unknown side effects.
// (These are described in comments after the table definition.)  Script
// functions that are not listed as assumed to not be "special", i.e. known
// to the event engine.

// Does not change script-level state (though may change internal state).
#define ATTR_NO_SCRIPT_SIDE_EFFECTS 0x1

// Does not change any Zeek state, internal or external. (May change
// state outside of Zeek, such as file system elements.) Implies
// ATTR_NO_SCRIPT_SIDE_EFFECTS.
#define ATTR_NO_ZEEK_SIDE_EFFECTS 0x2

// Calls made with the same arguments yield the same results. Implies
// ATTR_NO_ZEEK_SIDE_EFFECTS.
#define ATTR_IDEMPOTENT 0x4

// The event engine knows about this script function and may call it
// during its processing.
#define ATTR_SPECIAL_SCRIPT_FUNC 0x8

// ZAM knows about this script function and will replace it with specialized
// instructions.
#define ATTR_ZAM_REPLACEABLE_SCRIPT_FUNC 0x10

static std::unordered_map<std::string, unsigned int> func_attrs = {
    // Script functions.
    {"Analyzer::disabling_analyzer", ATTR_SPECIAL_SCRIPT_FUNC},
    {"Log::__default_rotation_postprocessor", ATTR_SPECIAL_SCRIPT_FUNC},
    {"Log::empty_post_delay_cb", ATTR_SPECIAL_SCRIPT_FUNC},
    {"Log::log_stream_policy", ATTR_SPECIAL_SCRIPT_FUNC},
    {"Log::rotation_format_func", ATTR_SPECIAL_SCRIPT_FUNC},
    {"Supervisor::stderr_hook", ATTR_SPECIAL_SCRIPT_FUNC},
    {"Supervisor::stdout_hook", ATTR_SPECIAL_SCRIPT_FUNC},
    {"assertion_failure", ATTR_SPECIAL_SCRIPT_FUNC},
    {"assertion_result", ATTR_SPECIAL_SCRIPT_FUNC},
    {"discarder_check_icmp", ATTR_SPECIAL_SCRIPT_FUNC},
    {"discarder_check_ip", ATTR_SPECIAL_SCRIPT_FUNC},
    {"discarder_check_tcp", ATTR_SPECIAL_SCRIPT_FUNC},
    {"discarder_check_udp", ATTR_SPECIAL_SCRIPT_FUNC},
    {"from_json_default_key_mapper", ATTR_SPECIAL_SCRIPT_FUNC},

    {"id_string", ATTR_ZAM_REPLACEABLE_SCRIPT_FUNC},

    // BiFs.
    {"Analyzer::__disable_all_analyzers", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Analyzer::__disable_analyzer", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Analyzer::__enable_analyzer", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Analyzer::__has_tag", ATTR_IDEMPOTENT},
    {"Analyzer::__name", ATTR_IDEMPOTENT},
    {"Analyzer::__register_for_port", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Analyzer::__schedule_analyzer", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Analyzer::__tag", ATTR_IDEMPOTENT},
    {"FileExtract::__set_limit", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Files::__add_analyzer", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Files::__analyzer_enabled", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"Files::__analyzer_name", ATTR_IDEMPOTENT},
    {"Files::__disable_analyzer", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Files::__disable_reassembly", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Files::__enable_analyzer", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Files::__enable_reassembly", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Files::__file_exists", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"Files::__lookup_file", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"Files::__remove_analyzer", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Files::__set_reassembly_buffer", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Files::__set_timeout_interval", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Files::__stop", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Input::__create_analysis_stream", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Input::__create_event_stream", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Input::__create_table_stream", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Input::__force_update", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Input::__remove_stream", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Log::__add_filter", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Log::__create_stream", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Log::__delay_finish", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Log::__disable_stream", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Log::__enable_stream", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Log::__flush", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Log::__get_delay_queue_size", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"Log::__remove_filter", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Log::__remove_stream", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Log::__set_buf", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Log::__set_max_delay_interval", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Log::__set_max_delay_queue_size", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Option::any_set_to_any_vec", ATTR_IDEMPOTENT},
    {"Option::set_change_handler", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"PacketAnalyzer::GTPV1::remove_gtpv1_connection", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"PacketAnalyzer::TEREDO::remove_teredo_connection", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"PacketAnalyzer::__disable_analyzer", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"PacketAnalyzer::__enable_analyzer", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"PacketAnalyzer::__set_ignore_checksums_nets", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"PacketAnalyzer::register_packet_analyzer", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"PacketAnalyzer::register_protocol_detection", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"PacketAnalyzer::try_register_packet_analyzer_by_name", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Pcap::error", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Pcap::findalldevs", ATTR_IDEMPOTENT},
    {"Pcap::get_filter_state", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"Pcap::get_filter_state_string", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"Pcap::install_pcap_filter", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Pcap::precompile_pcap_filter", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Reporter::conn_weird", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Reporter::error", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Reporter::fatal", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Reporter::fatal_error_with_core", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Reporter::file_weird", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Reporter::flow_weird", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Reporter::get_weird_sampling_duration", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"Reporter::get_weird_sampling_global_list", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"Reporter::get_weird_sampling_rate", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"Reporter::get_weird_sampling_threshold", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"Reporter::get_weird_sampling_whitelist", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"Reporter::info", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Reporter::net_weird", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Reporter::set_weird_sampling_duration", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Reporter::set_weird_sampling_global_list", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Reporter::set_weird_sampling_rate", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Reporter::set_weird_sampling_threshold", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Reporter::set_weird_sampling_whitelist", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Reporter::warning", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Spicy::__resource_usage", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"Spicy::__toggle_analyzer", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Supervisor::__create", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Supervisor::__destroy", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Supervisor::__init_cluster", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Supervisor::__is_supervised", ATTR_IDEMPOTENT},
    {"Supervisor::__is_supervisor", ATTR_IDEMPOTENT},
    // Note, the following is not idempotent since it can't be called during
    // initialization.
    {"Supervisor::__node", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"Supervisor::__restart", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Supervisor::__status", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"Supervisor::__stem_pid", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__collect_histogram_metrics", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__collect_metrics", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__dbl_counter_family", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__dbl_counter_inc", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__dbl_counter_metric_get_or_add", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__dbl_counter_value", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__dbl_gauge_dec", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__dbl_gauge_family", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__dbl_gauge_inc", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__dbl_gauge_metric_get_or_add", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__dbl_gauge_value", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__dbl_histogram_family", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__dbl_histogram_metric_get_or_add", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__dbl_histogram_observe", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__dbl_histogram_sum", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__int_counter_family", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__int_counter_inc", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__int_counter_metric_get_or_add", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__int_counter_value", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__int_gauge_dec", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__int_gauge_family", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__int_gauge_inc", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__int_gauge_metric_get_or_add", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__int_gauge_value", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__int_histogram_family", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__int_histogram_metric_get_or_add", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__int_histogram_observe", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"Telemetry::__int_histogram_sum", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"__init_primary_bifs", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"__init_secondary_bifs", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"active_file", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"addr_to_counts", ATTR_IDEMPOTENT},
    {"addr_to_ptr_name", ATTR_IDEMPOTENT},
    {"addr_to_subnet", ATTR_IDEMPOTENT},
    {"all_set", ATTR_IDEMPOTENT},
    {"anonymize_addr", ATTR_IDEMPOTENT},
    {"any_set", ATTR_IDEMPOTENT},
    {"backtrace", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"bare_mode", ATTR_IDEMPOTENT},
    {"bloomfilter_add", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"bloomfilter_basic_init", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"bloomfilter_basic_init2", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"bloomfilter_clear", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"bloomfilter_counting_init", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"bloomfilter_decrement", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"bloomfilter_internal_state", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"bloomfilter_intersect", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"bloomfilter_lookup", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"bloomfilter_merge", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"bytestring_to_count", ATTR_IDEMPOTENT},
    {"bytestring_to_double", ATTR_IDEMPOTENT},
    {"bytestring_to_float", ATTR_IDEMPOTENT},
    {"bytestring_to_hexstr", ATTR_IDEMPOTENT},
    {"calc_next_rotate", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"cat", ATTR_IDEMPOTENT},
    {"cat_sep", ATTR_IDEMPOTENT},
    {"ceil", ATTR_IDEMPOTENT},
    {"check_subnet", ATTR_IDEMPOTENT},
    {"clean", ATTR_IDEMPOTENT},
    {"close", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"community_id_v1", ATTR_IDEMPOTENT},
    {"compress_path", ATTR_IDEMPOTENT},
    {"connection_exists", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"continue_processing", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"convert_for_pattern", ATTR_IDEMPOTENT},
    {"count_substr", ATTR_IDEMPOTENT},
    {"count_to_double", ATTR_IDEMPOTENT},
    {"count_to_port", ATTR_IDEMPOTENT},
    {"count_to_v4_addr", ATTR_IDEMPOTENT},
    {"counts_to_addr", ATTR_IDEMPOTENT},
    {"current_analyzer", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"current_event_time", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"current_time", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"decode_base64", ATTR_IDEMPOTENT},
    {"decode_base64_conn", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"decode_netbios_name", ATTR_IDEMPOTENT},
    {"decode_netbios_name_type", ATTR_IDEMPOTENT},
    {"disable_event_group", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"disable_module_events", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"do_profiling", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"double_to_count", ATTR_IDEMPOTENT},
    {"double_to_int", ATTR_IDEMPOTENT},
    {"double_to_interval", ATTR_IDEMPOTENT},
    {"double_to_time", ATTR_IDEMPOTENT},
    {"dump_current_packet", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"dump_packet", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"dump_rule_stats", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"edit", ATTR_IDEMPOTENT},
    {"enable_event_group", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"enable_module_events", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"enable_raw_output", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"encode_base64", ATTR_IDEMPOTENT},
    {"ends_with", ATTR_IDEMPOTENT},
    {"entropy_test_add", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"entropy_test_finish", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"entropy_test_init", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"enum_names", ATTR_IDEMPOTENT},
    {"enum_to_int", ATTR_IDEMPOTENT},
    {"escape_string", ATTR_IDEMPOTENT},
    {"exit", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"exp", ATTR_IDEMPOTENT},
    {"file_magic", ATTR_IDEMPOTENT},
    {"file_mode", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"file_size", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"filter_subnet_table", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"find_all", ATTR_IDEMPOTENT},
    {"find_all_ordered", ATTR_IDEMPOTENT},
    {"find_entropy", ATTR_IDEMPOTENT},
    {"find_last", ATTR_IDEMPOTENT},
    {"find_str", ATTR_IDEMPOTENT},
    {"floor", ATTR_IDEMPOTENT},
    {"flush_all", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"fmt", ATTR_IDEMPOTENT},
    {"fmt_ftp_port", ATTR_IDEMPOTENT},
    {"fnv1a32", ATTR_IDEMPOTENT},
    {"generate_all_events", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"get_broker_stats", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_conn_stats", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_conn_transport_proto", ATTR_IDEMPOTENT},
    {"get_contents_file", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_current_conn_bytes_threshold", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_current_conn_duration_threshold", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_current_conn_packets_threshold", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_current_packet", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_current_packet_header", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_dns_stats", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_event_handler_stats", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_event_stats", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_file_analysis_stats", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_file_name", ATTR_IDEMPOTENT},
    {"get_gap_stats", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_identifier_comments", ATTR_IDEMPOTENT},
    {"get_identifier_declaring_script", ATTR_IDEMPOTENT},
    {"get_login_state", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_matcher_stats", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_net_stats", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_orig_seq", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_package_readme", ATTR_IDEMPOTENT},
    {"get_port_transport_proto", ATTR_IDEMPOTENT},
    {"get_proc_stats", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_reassembler_stats", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_record_field_comments", ATTR_IDEMPOTENT},
    {"get_record_field_declaring_script", ATTR_IDEMPOTENT},
    {"get_reporter_stats", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_resp_seq", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_script_comments", ATTR_IDEMPOTENT},
    {"get_thread_stats", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"get_timer_stats", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"getenv", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"gethostname", ATTR_IDEMPOTENT},
    {"getpid", ATTR_IDEMPOTENT},
    {"global_container_footprints", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"global_ids", ATTR_IDEMPOTENT},
    // Not available during initialization, so not idempotent.
    {"global_options", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"gsub", ATTR_IDEMPOTENT},
    {"has_event_group", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"has_module_events", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"have_spicy", ATTR_IDEMPOTENT},
    {"have_spicy_analyzers", ATTR_IDEMPOTENT},
    {"haversine_distance", ATTR_IDEMPOTENT},
    {"hexdump", ATTR_IDEMPOTENT},
    {"hexstr_to_bytestring", ATTR_IDEMPOTENT},
    {"hll_cardinality_add", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"hll_cardinality_copy", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"hll_cardinality_estimate", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"hll_cardinality_init", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"hll_cardinality_merge_into", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"hrw_weight", ATTR_IDEMPOTENT},
    {"identify_data", ATTR_IDEMPOTENT},
    {"install_dst_addr_filter", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"install_dst_net_filter", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"install_src_addr_filter", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"install_src_net_filter", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"int_to_count", ATTR_IDEMPOTENT},
    {"int_to_double", ATTR_IDEMPOTENT},
    {"interval_to_double", ATTR_IDEMPOTENT},
    {"is_alnum", ATTR_IDEMPOTENT},
    {"is_alpha", ATTR_IDEMPOTENT},
    {"is_ascii", ATTR_IDEMPOTENT},
    {"is_file_analyzer", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"is_icmp_port", ATTR_IDEMPOTENT},
    {"is_local_interface", ATTR_IDEMPOTENT},
    {"is_num", ATTR_IDEMPOTENT},
    {"is_packet_analyzer", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"is_processing_suspended", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"is_protocol_analyzer", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"is_remote_event", ATTR_IDEMPOTENT},
    {"is_tcp_port", ATTR_IDEMPOTENT},
    {"is_udp_port", ATTR_IDEMPOTENT},
    {"is_v4_addr", ATTR_IDEMPOTENT},
    {"is_v4_subnet", ATTR_IDEMPOTENT},
    {"is_v6_addr", ATTR_IDEMPOTENT},
    {"is_v6_subnet", ATTR_IDEMPOTENT},
    {"is_valid_ip", ATTR_IDEMPOTENT},
    {"join_string_set", ATTR_IDEMPOTENT},
    {"join_string_vec", ATTR_IDEMPOTENT},
    {"levenshtein_distance", ATTR_IDEMPOTENT},
    {"ljust", ATTR_IDEMPOTENT},
    {"ln", ATTR_IDEMPOTENT},
    {"load_CPP", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"log10", ATTR_IDEMPOTENT},
    {"log2", ATTR_IDEMPOTENT},
    {"lookup_ID", ATTR_IDEMPOTENT},
    {"lookup_addr", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"lookup_autonomous_system", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"lookup_connection", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"lookup_hostname", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"lookup_hostname_txt", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"lookup_location", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"lstrip", ATTR_IDEMPOTENT},
    {"mask_addr", ATTR_IDEMPOTENT},
    {"match_signatures", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"matching_subnets", ATTR_IDEMPOTENT},
    {"md5_hash", ATTR_IDEMPOTENT},
    {"md5_hash_finish", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"md5_hash_init", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"md5_hash_update", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"md5_hmac", ATTR_IDEMPOTENT},
    {"mkdir", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"mmdb_open_asn_db", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"mmdb_open_location_db", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"network_time", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"open", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"open_for_append", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"packet_source", ATTR_IDEMPOTENT},
    {"paraglob_equals", ATTR_IDEMPOTENT},
    {"paraglob_init", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"paraglob_match", ATTR_IDEMPOTENT},
    {"parse_distinguished_name", ATTR_IDEMPOTENT},
    {"parse_eftp_port", ATTR_IDEMPOTENT},
    {"parse_ftp_epsv", ATTR_IDEMPOTENT},
    {"parse_ftp_pasv", ATTR_IDEMPOTENT},
    {"parse_ftp_port", ATTR_IDEMPOTENT},
    {"piped_exec", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"port_to_count", ATTR_IDEMPOTENT},
    {"pow", ATTR_IDEMPOTENT},
    {"preserve_prefix", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"preserve_subnet", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"print_raw", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"ptr_name_to_addr", ATTR_IDEMPOTENT},
    {"rand", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"raw_bytes_to_v4_addr", ATTR_IDEMPOTENT},
    {"raw_bytes_to_v6_addr", ATTR_IDEMPOTENT},
    {"reading_live_traffic", ATTR_IDEMPOTENT},
    {"reading_traces", ATTR_IDEMPOTENT},
    {"record_fields", ATTR_IDEMPOTENT},
    {"record_type_to_vector", ATTR_IDEMPOTENT},
    {"remask_addr", ATTR_IDEMPOTENT},
    {"remove_prefix", ATTR_IDEMPOTENT},
    {"remove_suffix", ATTR_IDEMPOTENT},
    {"rename", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"reverse", ATTR_IDEMPOTENT},
    {"rfind_str", ATTR_IDEMPOTENT},
    {"rjust", ATTR_IDEMPOTENT},
    {"rmdir", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"rotate_file", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"rotate_file_by_name", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"routing0_data_to_addrs", ATTR_IDEMPOTENT},
    {"rstrip", ATTR_IDEMPOTENT},
    {"safe_shell_quote", ATTR_IDEMPOTENT},
    {"same_object", ATTR_IDEMPOTENT},
    {"sct_verify", ATTR_IDEMPOTENT},
    {"set_buf", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"set_contents_file", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"set_current_conn_bytes_threshold", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"set_current_conn_duration_threshold", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"set_current_conn_packets_threshold", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"set_file_handle", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"set_inactivity_timeout", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"set_keys", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"set_login_state", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"set_network_time", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"set_record_packets", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"set_secret", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"set_ssl_established", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"setenv", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"sha1_hash", ATTR_IDEMPOTENT},
    {"sha1_hash_finish", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"sha1_hash_init", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"sha1_hash_update", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"sha256_hash", ATTR_IDEMPOTENT},
    {"sha256_hash_finish", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"sha256_hash_init", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"sha256_hash_update", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"skip_further_processing", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"skip_http_entity_data", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"skip_smtp_data", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"split_string", ATTR_IDEMPOTENT},
    {"split_string1", ATTR_IDEMPOTENT},
    {"split_string_all", ATTR_IDEMPOTENT},
    {"split_string_n", ATTR_IDEMPOTENT},
    {"sqrt", ATTR_IDEMPOTENT},
    {"srand", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"starts_with", ATTR_IDEMPOTENT},
    {"str_smith_waterman", ATTR_IDEMPOTENT},
    {"str_split_indices", ATTR_IDEMPOTENT},
    {"strcmp", ATTR_IDEMPOTENT},
    {"strftime", ATTR_IDEMPOTENT},
    {"string_cat", ATTR_IDEMPOTENT},
    {"string_fill", ATTR_IDEMPOTENT},
    {"string_to_ascii_hex", ATTR_IDEMPOTENT},
    {"string_to_pattern", ATTR_IDEMPOTENT},
    {"strip", ATTR_IDEMPOTENT},
    {"strptime", ATTR_IDEMPOTENT},
    {"strstr", ATTR_IDEMPOTENT},
    {"sub", ATTR_IDEMPOTENT},
    {"sub_bytes", ATTR_IDEMPOTENT},
    {"subnet_to_addr", ATTR_IDEMPOTENT},
    {"subnet_width", ATTR_IDEMPOTENT},
    {"subst_string", ATTR_IDEMPOTENT},
    {"suspend_processing", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"swap_case", ATTR_IDEMPOTENT},
    {"syslog", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"system", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"system_env", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"table_keys", ATTR_IDEMPOTENT},
    {"table_pattern_matcher_stats", ATTR_IDEMPOTENT},
    {"table_values", ATTR_IDEMPOTENT},
    {"terminate", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"time_to_double", ATTR_IDEMPOTENT},
    {"to_addr", ATTR_IDEMPOTENT},
    {"to_count", ATTR_IDEMPOTENT},
    {"to_double", ATTR_IDEMPOTENT},
    {"to_int", ATTR_IDEMPOTENT},
    {"to_json", ATTR_IDEMPOTENT},
    {"to_lower", ATTR_IDEMPOTENT},
    {"to_port", ATTR_IDEMPOTENT},
    {"to_string_literal", ATTR_IDEMPOTENT},
    {"to_subnet", ATTR_IDEMPOTENT},
    {"to_title", ATTR_IDEMPOTENT},
    {"to_upper", ATTR_IDEMPOTENT},
    {"topk_add", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"topk_count", ATTR_IDEMPOTENT},
    {"topk_epsilon", ATTR_IDEMPOTENT},
    {"topk_get_top", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"topk_init", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"topk_merge", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"topk_merge_prune", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"topk_size", ATTR_IDEMPOTENT},
    {"topk_sum", ATTR_IDEMPOTENT},
    {"type_aliases", ATTR_IDEMPOTENT},
    {"type_name", ATTR_IDEMPOTENT},
    {"unescape_URI", ATTR_IDEMPOTENT},
    {"uninstall_dst_addr_filter", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"uninstall_dst_net_filter", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"uninstall_src_addr_filter", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"uninstall_src_net_filter", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"unique_id", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"unique_id_from", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"unlink", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"uuid_to_string", ATTR_IDEMPOTENT},
    {"val_footprint", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"write_file", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"x509_check_cert_hostname", ATTR_IDEMPOTENT},
    {"x509_check_hostname", ATTR_IDEMPOTENT},
    {"x509_from_der", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"x509_get_certificate_string", ATTR_IDEMPOTENT},
    {"x509_issuer_name_hash", ATTR_IDEMPOTENT},
    {"x509_ocsp_verify", ATTR_IDEMPOTENT},
    {"x509_parse", ATTR_IDEMPOTENT},
    {"x509_set_certificate_cache", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"x509_set_certificate_cache_hit_callback", ATTR_NO_SCRIPT_SIDE_EFFECTS},
    {"x509_spki_hash", ATTR_IDEMPOTENT},
    {"x509_subject_name_hash", ATTR_IDEMPOTENT},
    {"x509_verify", ATTR_IDEMPOTENT},
    {"zeek_args", ATTR_IDEMPOTENT},
    {"zeek_is_terminating", ATTR_NO_ZEEK_SIDE_EFFECTS},
    {"zeek_version", ATTR_IDEMPOTENT},
    {"zfill", ATTR_IDEMPOTENT},
};

// Ones not listed:
//
// Broker::*
//	These can manipulate unspecified (at script level) records.
//
// Cluster::publish_hrw
// Cluster::publish_rr
//	These call script functions to get topic names.
//
// Log::__delay
//	Can invoke a callback function specified at run-time.
//
// Log::__write
//	Calls log policy functions.
//
// Option::set
//	Both explicitly changes a global and potentially calls a
//	function specified at run-time.
//
// clear_table
//	Both clears a set/table and potentially calls an &on_change handler.
//
// disable_analyzer
//	Can call Analyzer::disabling_analyzer hook.
//
// from_json
//	Can call a normalization function.
//
// order
//	Can call a comparison function.
//
// resize
//	Changes a vector in place.
//
// sort
//	Both changes a vector in place and can call an arbitrary comparison
//	function.
//
// Some of these have side effects that could be checked for in a specific
// context, but the gains from doing so likely aren't worth the complexity.

bool is_special_script_func(const std::string& func_name) {
    auto f_attr = func_attrs.find(func_name);
    return f_attr != func_attrs.end() && (f_attr->second & ATTR_SPECIAL_SCRIPT_FUNC) != 0;
}

bool is_ZAM_replaceable_script_func(const std::string& func_name) {
    auto f_attr = func_attrs.find(func_name);
    return f_attr != func_attrs.end() && (f_attr->second & ATTR_ZAM_REPLACEABLE_SCRIPT_FUNC) != 0;
}

bool is_idempotent(const std::string& func_name) {
    auto f_attr = func_attrs.find(func_name);
    return f_attr != func_attrs.end() && (f_attr->second & ATTR_IDEMPOTENT) != 0;
}

bool has_script_side_effects(const std::string& func_name) {
    auto f_attr = func_attrs.find(func_name);
    if ( f_attr == func_attrs.end() )
        // We don't know about it, so be conservative.
        return true;

    return (f_attr->second & (ATTR_NO_SCRIPT_SIDE_EFFECTS | ATTR_NO_ZEEK_SIDE_EFFECTS | ATTR_IDEMPOTENT)) == 0;
}

} // namespace zeek::detail
