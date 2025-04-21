# This tests that the HTTP analyzer handles filenames over HTTP correctly.
#
# @TEST-EXEC: zeek -C -r $TRACES/http/http_small_case.pcap
# @TEST-EXEC: ! grep -q "not a http reply line" analyzer.log dpd.log
# @TEST-EXEC: rm *log
# @TEST-EXEC: zeek -C -r $TRACES/http/http_small_case_nonstandard_port.pcap
# @TEST-EXEC: ! grep -q "not a http reply line" analyzer.log dpd.log