# @TEST-DOC: Baseline the behavior documented around corrupt UDP checksums, packet counts and history.
#
# @TEST-EXEC: zeek -r $TRACES/dns/dns-corrupt.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid orig_pkts resp_pkts history conn_state conn.log
# @TEST-EXEC: zeek -r $TRACES/dns/dns-corrupt.pcap %INPUT PacketAnalyzer::checksum_validation=PacketAnalyzer::VALIDATION_ACTIVE
# @TEST-EXEC: mv conn.log conn-drop.log
# @TEST-EXEC: btest-diff-cut -m uid orig_pkts resp_pkts history conn_state conn-drop.log

@load base/protocols/conn
