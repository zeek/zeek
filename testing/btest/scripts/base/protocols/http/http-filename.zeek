# This tests that the HTTP analyzer handles filenames over HTTP correctly.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/http-filename.pcap %INPUT
# @TEST-EXEC: btest-diff http.log

@load base/protocols/http
