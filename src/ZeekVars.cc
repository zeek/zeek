// See the file "COPYING" in the main distribution directory for copyright.

#include "ZeekVars.h"
#include "Var.h"
#include "NetVar.h"
#include "Scope.h"

IntrusivePtr<RecordType> zeek::vars::conn_id;
IntrusivePtr<RecordType> zeek::vars::endpoint;
IntrusivePtr<RecordType> zeek::vars::connection;
IntrusivePtr<RecordType> zeek::vars::fa_file;
IntrusivePtr<RecordType> zeek::vars::fa_metadata;
IntrusivePtr<EnumType> zeek::vars::transport_proto;
IntrusivePtr<TableType> zeek::vars::string_set;
IntrusivePtr<TableType> zeek::vars::string_array;
IntrusivePtr<TableType> zeek::vars::count_set;
IntrusivePtr<VectorType> zeek::vars::string_vec;
IntrusivePtr<VectorType> zeek::vars::index_vec;

void zeek::vars::detail::init()
	{
	// Types
	conn_id = zeek::lookup_type<RecordType>("conn_id");
	endpoint = zeek::lookup_type<RecordType>("endpoint");
	connection = zeek::lookup_type<RecordType>("connection");
	fa_file = zeek::lookup_type<RecordType>("fa_file");
	fa_metadata = zeek::lookup_type<RecordType>("fa_metadata");
	transport_proto = zeek::lookup_type<EnumType>("transport_proto");
	string_set = zeek::lookup_type<TableType>("string_set");
	string_array = zeek::lookup_type<TableType>("string_array");
	count_set = zeek::lookup_type<TableType>("count_set");
	string_vec = zeek::lookup_type<VectorType>("string_vec");
	index_vec = zeek::lookup_type<VectorType>("index_vec");

	// Note: to bypass deprecation warnings on setting the legacy globals,
	// CMake was told to compile this file with -Wno-deprecated-declarations.
	// Once the legacy globals are removed, that compile flag can go also.
	::conn_id = conn_id.get();
	::endpoint = endpoint.get();
	::connection_type = connection.get();
	::fa_file_type = fa_file.get();
	::fa_metadata_type = fa_metadata.get();
	::icmp_conn = zeek::lookup_type("icmp_conn")->AsRecordType();
	::icmp_context = zeek::lookup_type("icmp_context")->AsRecordType();
	::signature_state = zeek::lookup_type("signature_state")->AsRecordType();
	::SYN_packet = zeek::lookup_type("SYN_packet")->AsRecordType();
	::pcap_packet = zeek::lookup_type("pcap_packet")->AsRecordType();
	::raw_pkt_hdr_type = zeek::lookup_type("raw_pkt_hdr")->AsRecordType();
	::l2_hdr_type = zeek::lookup_type("l2_hdr")->AsRecordType();
	::transport_proto = transport_proto.get();
	::string_set = string_set.get();
	::string_array = string_array.get();
	::count_set = count_set.get();
	::string_vec = string_vec.get();
	::index_vec = index_vec.get();
	::mime_matches = zeek::lookup_type("mime_matches")->AsVectorType();
	::mime_match = zeek::lookup_type("mime_match")->AsRecordType();
	::socks_address = zeek::lookup_type("SOCKS::Address")->AsRecordType();
	::mime_header_rec = zeek::lookup_type("mime_header_rec")->AsRecordType();
	::mime_header_list = zeek::lookup_type("mime_header_list")->AsTableType();
	::http_stats_rec = zeek::lookup_type("http_stats_rec")->AsRecordType();
	::http_message_stat = zeek::lookup_type("http_message_stat")->AsRecordType();
	::pm_mapping = zeek::lookup_type("pm_mapping")->AsRecordType();
	::pm_mappings = zeek::lookup_type("pm_mappings")->AsTableType();
	::pm_port_request = zeek::lookup_type("pm_port_request")->AsRecordType();
	::pm_callit_request = zeek::lookup_type("pm_callit_request")->AsRecordType();
	::geo_location = zeek::lookup_type("geo_location")->AsRecordType();
	::entropy_test_result = zeek::lookup_type("entropy_test_result")->AsRecordType();
	::dns_msg = zeek::lookup_type("dns_msg")->AsRecordType();
	::dns_answer = zeek::lookup_type("dns_answer")->AsRecordType();
	::dns_soa = zeek::lookup_type("dns_soa")->AsRecordType();
	::dns_edns_additional = zeek::lookup_type("dns_edns_additional")->AsRecordType();
	::dns_tsig_additional = zeek::lookup_type("dns_tsig_additional")->AsRecordType();
	::dns_rrsig_rr = zeek::lookup_type("dns_rrsig_rr")->AsRecordType();
	::dns_dnskey_rr = zeek::lookup_type("dns_dnskey_rr")->AsRecordType();
	::dns_nsec3_rr = zeek::lookup_type("dns_nsec3_rr")->AsRecordType();
	::dns_ds_rr = zeek::lookup_type("dns_ds_rr")->AsRecordType();
	::rotate_info = zeek::lookup_type("rotate_info")->AsRecordType();
	::irc_join_list = zeek::lookup_type("irc_join_list")->AsTableType();
	::irc_join_info = zeek::lookup_type("irc_join_info")->AsRecordType();
	::script_id = zeek::lookup_type("script_id")->AsRecordType();
	::id_table = zeek::lookup_type("id_table")->AsTableType();
	::record_field = zeek::lookup_type("record_field")->AsRecordType();
	::record_field_table = zeek::lookup_type("record_field_table")->AsTableType();
	::call_argument = zeek::lookup_type("call_argument")->AsRecordType();
	::call_argument_vector = zeek::lookup_type("call_argument_vector")->AsVectorType();

	::log_rotate_base_time = zeek::lookup_val("log_rotate_base_time")->AsStringVal();
	::pkt_profile_file = zeek::lookup_val("pkt_profile_file").get();
	::likely_server_ports = zeek::lookup_val("likely_server_ports")->AsTableVal();
	::tcp_content_delivery_ports_orig = zeek::lookup_val("tcp_content_delivery_ports_orig")->AsTableVal();
	::tcp_content_delivery_ports_resp = zeek::lookup_val("tcp_content_delivery_ports_resp")->AsTableVal();
	::stp_skip_src = zeek::lookup_val("stp_skip_src")->AsTableVal();
	::dns_skip_auth = zeek::lookup_val("dns_skip_auth")->AsTableVal();
	::dns_skip_addl = zeek::lookup_val("dns_skip_addl")->AsTableVal();
	::udp_content_ports = zeek::lookup_val("udp_content_ports")->AsTableVal();
	::udp_content_delivery_ports_orig = zeek::lookup_val("udp_content_delivery_ports_orig")->AsTableVal();
	::udp_content_delivery_ports_resp = zeek::lookup_val("udp_content_delivery_ports_resp")->AsTableVal();
	::profiling_file = zeek::lookup_val("profiling_file").get();
	::global_hash_seed = zeek::lookup_val("global_hash_seed")->AsStringVal();
	::tcp_reassembler_ports_orig = zeek::lookup_val("tcp_reassembler_ports_orig")->AsTableVal();
	::tcp_reassembler_ports_resp = zeek::lookup_val("tcp_reassembler_ports_resp")->AsTableVal();
	::peer_description = zeek::lookup_val("peer_description")->AsStringVal();
	::trace_output_file = zeek::lookup_val("trace_output_file")->AsStringVal();
	::cmd_line_bpf_filter = zeek::lookup_val("cmd_line_bpf_filter")->AsStringVal();

	auto anon_id = global_scope()->Lookup("preserve_orig_addr");

	if ( anon_id )
		preserve_orig_addr = anon_id->GetVal()->AsTableVal();

	anon_id = global_scope()->Lookup("preserve_resp_addr");

	if ( anon_id )
		preserve_resp_addr = anon_id->GetVal()->AsTableVal();

	anon_id = global_scope()->Lookup("preserve_other_addr");

	if ( anon_id )
		preserve_other_addr = anon_id->GetVal()->AsTableVal();
	}
