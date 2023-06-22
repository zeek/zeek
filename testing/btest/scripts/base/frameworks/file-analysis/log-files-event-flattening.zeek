# @TEST-DOC: Implement Files::log_files and verify it is seeing unique File::Info records.
# @TEST-EXEC: zeek -b -r $TRACES/http/concurrent-range-requests.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/frameworks/files
@load base/protocols/http

event Files::log_files(rec: Files::Info)
        {
        print rec$uid, rec$id;
        }
