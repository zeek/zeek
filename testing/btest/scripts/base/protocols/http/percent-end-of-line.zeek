# @TEST-EXEC: zeek -Cr $TRACES/http/percent-end-of-line.pcap %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff weird.log

