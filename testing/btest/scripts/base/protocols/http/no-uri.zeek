# @TEST-EXEC: zeek -Cr $TRACES/http/no-uri.pcap %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff weird.log

