
#include "NetVar.h"
#include "Var.h"
#include "ID.h"
#include "Scope.h"

namespace zeek {

// Compiled separately to avoid deprecation warnings at the assignment sites.
void zeek_legacy_netvar_init()
	{
	::conn_id = zeek::id::conn_id.get();
	::endpoint = zeek::id::endpoint.get();
	::connection_type = zeek::id::connection.get();
	::fa_file_type = zeek::id::fa_file.get();
	::fa_metadata_type = zeek::id::fa_metadata.get();
	::icmp_conn = zeek::id::find_type("icmp_conn")->AsRecordType();
	::icmp_context = zeek::id::find_type("icmp_context")->AsRecordType();
	::signature_state = zeek::id::find_type("signature_state")->AsRecordType();
	::SYN_packet = zeek::id::find_type("SYN_packet")->AsRecordType();
	::pcap_packet = zeek::id::find_type("pcap_packet")->AsRecordType();
	::raw_pkt_hdr_type = zeek::id::find_type("raw_pkt_hdr")->AsRecordType();
	::l2_hdr_type = zeek::id::find_type("l2_hdr")->AsRecordType();
	::transport_proto = zeek::id::transport_proto.get();
	::string_set = zeek::id::string_set.get();
	::string_array = zeek::id::string_array.get();
	::count_set = zeek::id::count_set.get();
	::string_vec = zeek::id::string_vec.get();
	::index_vec = zeek::id::index_vec.get();
	::mime_matches = zeek::id::find_type("mime_matches")->AsVectorType();
	::mime_match = zeek::id::find_type("mime_match")->AsRecordType();
	::socks_address = zeek::id::find_type("SOCKS::Address")->AsRecordType();
	::mime_header_rec = zeek::id::find_type("mime_header_rec")->AsRecordType();
	::mime_header_list = zeek::id::find_type("mime_header_list")->AsTableType();
	::http_stats_rec = zeek::id::find_type("http_stats_rec")->AsRecordType();
	::http_message_stat = zeek::id::find_type("http_message_stat")->AsRecordType();
	::pm_mapping = zeek::id::find_type("pm_mapping")->AsRecordType();
	::pm_mappings = zeek::id::find_type("pm_mappings")->AsTableType();
	::pm_port_request = zeek::id::find_type("pm_port_request")->AsRecordType();
	::pm_callit_request = zeek::id::find_type("pm_callit_request")->AsRecordType();
	::geo_location = zeek::id::find_type("geo_location")->AsRecordType();
	::entropy_test_result = zeek::id::find_type("entropy_test_result")->AsRecordType();
	::dns_msg = zeek::id::find_type("dns_msg")->AsRecordType();
	::dns_answer = zeek::id::find_type("dns_answer")->AsRecordType();
	::dns_soa = zeek::id::find_type("dns_soa")->AsRecordType();
	::dns_edns_additional = zeek::id::find_type("dns_edns_additional")->AsRecordType();
	::dns_edns_ecs = zeek::id::find_type("dns_edns_ecs")->AsRecordType();
	::dns_tsig_additional = zeek::id::find_type("dns_tsig_additional")->AsRecordType();
	::dns_rrsig_rr = zeek::id::find_type("dns_rrsig_rr")->AsRecordType();
	::dns_dnskey_rr = zeek::id::find_type("dns_dnskey_rr")->AsRecordType();
	::dns_nsec3_rr = zeek::id::find_type("dns_nsec3_rr")->AsRecordType();
	::dns_ds_rr = zeek::id::find_type("dns_ds_rr")->AsRecordType();
	::rotate_info = zeek::id::find_type("rotate_info")->AsRecordType();
	::irc_join_list = zeek::id::find_type("irc_join_list")->AsTableType();
	::irc_join_info = zeek::id::find_type("irc_join_info")->AsRecordType();
	::script_id = zeek::id::find_type("script_id")->AsRecordType();
	::id_table = zeek::id::find_type("id_table")->AsTableType();
	::record_field = zeek::id::find_type("record_field")->AsRecordType();
	::record_field_table = zeek::id::find_type("record_field_table")->AsTableType();
	::call_argument = zeek::id::find_type("call_argument")->AsRecordType();
	::call_argument_vector = zeek::id::find_type("call_argument_vector")->AsVectorType();

	::log_rotate_base_time = zeek::id::find_val("log_rotate_base_time")->AsStringVal();
	::pkt_profile_file = zeek::id::find_val("pkt_profile_file").get();
	::likely_server_ports = zeek::id::find_val("likely_server_ports")->AsTableVal();
	::tcp_content_delivery_ports_orig = zeek::id::find_val("tcp_content_delivery_ports_orig")->AsTableVal();
	::tcp_content_delivery_ports_resp = zeek::id::find_val("tcp_content_delivery_ports_resp")->AsTableVal();
	::stp_skip_src = zeek::id::find_val("stp_skip_src")->AsTableVal();
	::dns_skip_auth = zeek::id::find_val("dns_skip_auth")->AsTableVal();
	::dns_skip_addl = zeek::id::find_val("dns_skip_addl")->AsTableVal();
	::udp_content_ports = zeek::id::find_val("udp_content_ports")->AsTableVal();
	::udp_content_delivery_ports_orig = zeek::id::find_val("udp_content_delivery_ports_orig")->AsTableVal();
	::udp_content_delivery_ports_resp = zeek::id::find_val("udp_content_delivery_ports_resp")->AsTableVal();
	::profiling_file = zeek::id::find_val("profiling_file").get();
	::global_hash_seed = zeek::id::find_val("global_hash_seed")->AsStringVal();
	::tcp_reassembler_ports_orig = zeek::id::find_val("tcp_reassembler_ports_orig")->AsTableVal();
	::tcp_reassembler_ports_resp = zeek::id::find_val("tcp_reassembler_ports_resp")->AsTableVal();
	::peer_description = zeek::id::find_val("peer_description")->AsStringVal();
	::trace_output_file = zeek::id::find_val("trace_output_file")->AsStringVal();
	::cmd_line_bpf_filter = zeek::id::find_val("cmd_line_bpf_filter")->AsStringVal();

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

} // namespace zeek
