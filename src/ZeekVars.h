// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Val.h"
#include "Type.h"
#include "IntrusivePtr.h"

namespace zeek { namespace vars { namespace detail {
void Init();
}}}

namespace zeek { namespace vars {

// Types
extern IntrusivePtr<RecordType> conn_id;
extern IntrusivePtr<RecordType> endpoint;
extern IntrusivePtr<RecordType> endpoint_stats;
extern IntrusivePtr<RecordType> connection_type;
extern IntrusivePtr<RecordType> fa_file_type;
extern IntrusivePtr<RecordType> fa_metadata_type;
extern IntrusivePtr<RecordType> icmp_conn;
extern IntrusivePtr<RecordType> icmp_context;
extern IntrusivePtr<RecordType> signature_state;
extern IntrusivePtr<RecordType> SYN_packet;
extern IntrusivePtr<RecordType> pcap_packet;
extern IntrusivePtr<RecordType> raw_pkt_hdr_type;
extern IntrusivePtr<RecordType> l2_hdr_type;
extern IntrusivePtr<EnumType> transport_proto;
extern IntrusivePtr<TableType> string_set;
extern IntrusivePtr<TableType> string_array;
extern IntrusivePtr<TableType> count_set;
extern IntrusivePtr<VectorType> string_vec;
extern IntrusivePtr<VectorType> index_vec;
extern IntrusivePtr<VectorType> mime_matches;
extern IntrusivePtr<RecordType> mime_match;
extern IntrusivePtr<RecordType> socks_address;
extern IntrusivePtr<RecordType> mime_header_rec;
extern IntrusivePtr<TableType> mime_header_list;
extern IntrusivePtr<RecordType> http_stats_rec;
extern IntrusivePtr<RecordType> http_message_stat;
extern IntrusivePtr<RecordType> pm_mapping;
extern IntrusivePtr<TableType> pm_mappings;
extern IntrusivePtr<RecordType> pm_port_request;
extern IntrusivePtr<RecordType> pm_callit_request;
extern IntrusivePtr<RecordType> geo_location;
extern IntrusivePtr<RecordType> entropy_test_result;
extern IntrusivePtr<RecordType> dns_msg;
extern IntrusivePtr<RecordType> dns_answer;
extern IntrusivePtr<RecordType> dns_soa;
extern IntrusivePtr<RecordType> dns_edns_additional;
extern IntrusivePtr<RecordType> dns_tsig_additional;
extern IntrusivePtr<RecordType> dns_rrsig_rr;
extern IntrusivePtr<RecordType> dns_dnskey_rr;
extern IntrusivePtr<RecordType> dns_nsec3_rr;
extern IntrusivePtr<RecordType> dns_ds_rr;
extern IntrusivePtr<RecordType> rotate_info;
extern IntrusivePtr<TableType> irc_join_list;
extern IntrusivePtr<RecordType> irc_join_info;
extern IntrusivePtr<RecordType> script_id;
extern IntrusivePtr<TableType> id_table;
extern IntrusivePtr<RecordType> record_field;
extern IntrusivePtr<TableType> record_field_table;
extern IntrusivePtr<RecordType> call_argument;
extern IntrusivePtr<VectorType> call_argument_vector;

}} // namespace zeek::vars
