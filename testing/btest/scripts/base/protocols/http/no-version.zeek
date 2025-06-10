# @TEST-EXEC: zeek -b -r $TRACES/http/no-version.pcap %INPUT
# @TEST-EXEC: btest-diff http.log

@load base/protocols/http
