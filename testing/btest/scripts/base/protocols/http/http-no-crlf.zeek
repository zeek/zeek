# This tests that the HTTP analyzer handles HTTP with no CRLF at end correctly.

# @TEST-EXEC: zeek -b -r $TRACES/http/no_crlf.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/conn
@load base/protocols/http
