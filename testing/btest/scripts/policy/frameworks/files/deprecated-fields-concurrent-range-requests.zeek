# @TEST-DOC: The pcap contains 3 connections with range requests for the same file. We expect 3 files.log entries all with the same fuid, but different uids. With the deprecated fields, we expect tx_hosts, rx_hosts and conn_uuids to agree with the uid and id fields.
# @TEST-EXEC: zeek -b -r $TRACES/http/concurrent-range-requests.pcap %INPUT 2>&1 > out
# @TEST-EXEC: mv files.log files.log.new
# @TEST-EXEC: mv out out.new
# @TEST-EXEC: btest-diff out.new
# @TEST-EXEC: btest-diff files.log.new

# @TEST-EXEC: zeek -b -r $TRACES/http/concurrent-range-requests.pcap %INPUT frameworks/files/deprecated-txhosts-rxhosts-connuids 2>&1 > out
# @TEST-EXEC: mv files.log files.log.deprecated
# @TEST-EXEC: mv out out.deprecated
# @TEST-EXEC: btest-diff out.deprecated
# @TEST-EXEC: btest-diff files.log.deprecated

@load base/frameworks/files
@load base/protocols/http
