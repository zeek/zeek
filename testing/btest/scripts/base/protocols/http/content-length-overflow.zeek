# @TEST-DOC: Regression test for crash when HTTP Content-Length exceeds INT_MAX. ContentLine_Analyzer::DoDeliver() used std::min<int>(plain_delivery_length, len) where plain_delivery_length is int64_t, causing signed integer overflow and memory corruption.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/content-length-overflow.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m http.log

@load base/protocols/conn
@load base/protocols/http
