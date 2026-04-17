# @TEST-EXEC: zeek -b -C -r $TRACES/dns/dns-invalid-names.pcap %INPUT > output
# @TEST-EXEC: test ! -s output
# @TEST-EXEC: grep -q 'DNS_label_len_gt_pkt' weird.log
# @TEST-EXEC: grep -q 'DNS_label_forward_compress_offset' weird.log
# @TEST-EXEC: grep -q 'dns_invalid_name' weird.log
# @TEST-EXEC: test "$(grep -c 'DNS_label_len_gt_pkt' weird.log)" = "1"
# @TEST-EXEC: test "$(grep -c 'DNS_label_forward_compress_offset' weird.log)" = "1"
# @TEST-EXEC: test "$(grep -c 'dns_invalid_name' weird.log)" = "1"

@load base/frameworks/notice/weird
@load base/protocols/dns
