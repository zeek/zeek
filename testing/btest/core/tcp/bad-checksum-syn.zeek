# @TEST-DOC: Baseline the behavior documented around corrupt TCP checksums, packet counts and history.
#
# @TEST-EXEC: zeek -b -r $TRACES/tcp/syn-bad.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m uid orig_pkts resp_pkts history conn_state conn.log
# @TEST-EXEC: zeek -b -r $TRACES/tcp/syn-bad.pcap %INPUT drop_bad_checksums=T
# @TEST-EXEC: mv conn.log conn-drop.log
# @TEST-EXEC: btest-diff-cut -m uid orig_pkts resp_pkts history conn_state conn-drop.log

@load base/protocols/conn
