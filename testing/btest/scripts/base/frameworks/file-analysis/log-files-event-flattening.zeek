# @TEST-DOC: Implement Files::log_files and verify it is seeing unique File::Info records.
# @TEST-EXEC: zeek -b -r $TRACES/http/concurrent-range-requests.pcap uid-id.zeek >out.new
# @TEST-EXEC: zeek -b -r $TRACES/http/concurrent-range-requests.pcap frameworks/files/deprecated-txhosts-rxhosts-connuids uid-id-deprecated.zeek >out.deprecated
# @TEST-EXEC: btest-diff out.new
# @TEST-EXEC: btest-diff out.deprecated

@TEST-START-FILE uid-id.zeek
@load base/frameworks/files
@load base/protocols/http

event Files::log_files(rec: Files::Info)
        {
        print rec$uid, rec$id;
        }
@TEST-END-FILE


@TEST-START-FILE uid-id-deprecated.zeek
@load base/frameworks/files
@load base/protocols/http

event Files::log_files(rec: Files::Info)
        {
        print rec$uid, rec$id, cat(rec$tx_hosts), cat(rec$rx_hosts), cat(rec$conn_uids);
        }
@TEST-END-FILE
