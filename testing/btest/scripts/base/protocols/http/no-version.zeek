# @TEST-EXEC: zeek -b -Cr $TRACES/http/no-version.pcap %INPUT
# @TEST-EXEC: btest-diff http.log

@load base/protocols/http
