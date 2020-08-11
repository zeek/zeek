# @TEST-EXEC: zeek -b -C -r $TRACES/nflog-http.pcap %INPUT
# @TEST-EXEC: btest-diff http.log

@load base/protocols/http
