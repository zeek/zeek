# @TEST-DOC: Pcap contains concurrent range-requests for the same file. Prior to Zeek v5.1, there would have been just one files.log entry, now there are 3 all having the same fuid.
# @TEST-EXEC: zeek -b -r $TRACES/http/concurrent-range-requests.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff files.log

@load base/protocols/conn
@load base/protocols/http
