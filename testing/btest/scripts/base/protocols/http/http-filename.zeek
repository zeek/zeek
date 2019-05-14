# This tests that the HTTP analyzer handles filenames over HTTP correctly.
#
# @TEST-EXEC: zeek -r $TRACES/http/http-filename.pcap %INPUT
# @TEST-EXEC: btest-diff http.log

# The base analysis scripts are loaded by default.
#@load base/protocols/http

