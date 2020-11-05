
#include "NetVar.h"
#include "Var.h"
#include "ID.h"
#include "Scope.h"

namespace zeek::detail {

// Compiled separately to avoid deprecation warnings at the assignment sites.
void zeek_legacy_netvar_init()
	{
	::conn_id = id::conn_id.get();
	::endpoint = id::endpoint.get();
	::connection_type = id::connection.get();
	::fa_file_type = id::fa_file.get();
	::fa_metadata_type = id::fa_metadata.get();
	::icmp_conn = id::find_type("icmp_conn")->AsRecordType();
	::icmp_context = id::find_type("icmp_context")->AsRecordType();
	::signature_state = id::find_type("signature_state")->AsRecordType();
	::SYN_packet = id::find_type("SYN_packet")->AsRecordType();
	::pcap_packet = id::find_type("pcap_packet")->AsRecordType();
	::raw_pkt_hdr_type = id::find_type("raw_pkt_hdr")->AsRecordType();
	::l2_hdr_type = id::find_type("l2_hdr")->AsRecordType();
	::transport_proto = id::transport_proto.get();
	::string_set = id::string_set.get();
	::string_array = id::string_array.get();
	::count_set = id::count_set.get();
	::string_vec = id::string_vec.get();
	::index_vec = id::index_vec.get();
	::mime_matches = id::find_type("mime_matches")->AsVectorType();
	::mime_match = id::find_type("mime_match")->AsRecordType();
	::socks_address = id::find_type("SOCKS::Address")->AsRecordType();
	::mime_header_rec = id::find_type("mime_header_rec")->AsRecordType();
	::mime_header_list = id::find_type("mime_header_list")->AsTableType();
	::http_stats_rec = id::find_type("http_stats_rec")->AsRecordType();
	::http_message_stat = id::find_type("http_message_stat")->AsRecordType();
	::pm_mapping = id::find_type("pm_mapping")->AsRecordType();
	::pm_mappings = id::find_type("pm_mappings")->AsTableType();
	::pm_port_request = id::find_type("pm_port_request")->AsRecordType();
	::pm_callit_request = id::find_type("pm_callit_request")->AsRecordType();
	::geo_location = id::find_type("geo_location")->AsRecordType();
	::entropy_test_result = id::find_type("entropy_test_result")->AsRecordType();
	::dns_msg = id::find_type("dns_msg")->AsRecordType();
	::dns_answer = id::find_type("dns_answer")->AsRecordType();
	::dns_soa = id::find_type("dns_soa")->AsRecordType();
	::dns_edns_additional = id::find_type("dns_edns_additional")->AsRecordType();
	::dns_edns_ecs = id::find_type("dns_edns_ecs")->AsRecordType();
	::dns_tsig_additional = id::find_type("dns_tsig_additional")->AsRecordType();
	::dns_rrsig_rr = id::find_type("dns_rrsig_rr")->AsRecordType();
	::dns_dnskey_rr = id::find_type("dns_dnskey_rr")->AsRecordType();
	::dns_nsec3_rr = id::find_type("dns_nsec3_rr")->AsRecordType();
	::dns_ds_rr = id::find_type("dns_ds_rr")->AsRecordType();
	::dns_binds_rr = id::find_type("dns_binds_rr")->AsRecordType();
	::rotate_info = id::find_type("rotate_info")->AsRecordType();
	::irc_join_list = id::find_type("irc_join_list")->AsTableType();
	::irc_join_info = id::find_type("irc_join_info")->AsRecordType();
	::script_id = id::find_type("script_id")->AsRecordType();
	::id_table = id::find_type("id_table")->AsTableType();
	::record_field = id::find_type("record_field")->AsRecordType();
	::record_field_table = id::find_type("record_field_table")->AsTableType();
	::call_argument = id::find_type("call_argument")->AsRecordType();
	::call_argument_vector = id::find_type("call_argument_vector")->AsVectorType();

	::log_rotate_base_time = id::find_val("log_rotate_base_time")->AsStringVal();
	::pkt_profile_file = id::find_val("pkt_profile_file").get();
	::likely_server_ports = id::find_val("likely_server_ports")->AsTableVal();
	::tcp_content_delivery_ports_orig = id::find_val("tcp_content_delivery_ports_orig")->AsTableVal();
	::tcp_content_delivery_ports_resp = id::find_val("tcp_content_delivery_ports_resp")->AsTableVal();
	::stp_skip_src = id::find_val("stp_skip_src")->AsTableVal();
	::dns_skip_auth = id::find_val("dns_skip_auth")->AsTableVal();
	::dns_skip_addl = id::find_val("dns_skip_addl")->AsTableVal();
	::udp_content_ports = id::find_val("udp_content_ports")->AsTableVal();
	::udp_content_delivery_ports_orig = id::find_val("udp_content_delivery_ports_orig")->AsTableVal();
	::udp_content_delivery_ports_resp = id::find_val("udp_content_delivery_ports_resp")->AsTableVal();
	::profiling_file = id::find_val("profiling_file").get();
	::global_hash_seed = id::find_val("global_hash_seed")->AsStringVal();
	::tcp_reassembler_ports_orig = id::find_val("tcp_reassembler_ports_orig")->AsTableVal();
	::tcp_reassembler_ports_resp = id::find_val("tcp_reassembler_ports_resp")->AsTableVal();
	::peer_description = id::find_val("peer_description")->AsStringVal();
	::trace_output_file = id::find_val("trace_output_file")->AsStringVal();
	::cmd_line_bpf_filter = id::find_val("cmd_line_bpf_filter")->AsStringVal();

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

} // namespace zeek::detail
