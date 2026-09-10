# @TEST-DOC: Check that prefix-matching logic for HTTP CONNECT requests doesn't mask later requests
# @TEST-EXEC: zeek -b -r $TRACES/http/connect-prefix-match.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m http.log

@load base/protocols/http
