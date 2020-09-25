# @TEST-EXEC: zeek -b -r $TRACES/http/bro.org-filtered.pcap %INPUT >out1 2>&1
# @TEST-EXEC: zeek -b -r $TRACES/http/bro.org-filtered.pcap %INPUT "FilteredTraceDetection::enable=F" >out2 2>&1
# @TEST-EXEC: zeek -b -r $TRACES/wikipedia-filtered-plus-udp.trace %INPUT >out3 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out1
# @TEST-EXEC: btest-diff out2
# @TEST-EXEC: btest-diff out3

@load base/misc/find-filtered-trace
