# @TEST-EXEC: zeek -Cr $TRACES/http/no-version.pcap %INPUT
# @TEST-EXEC: btest-diff http.log

