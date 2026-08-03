# @TEST-DOC: Test a large array gets cut off if it creates too many elements.
# @TEST-REQUIRES: have-spicy
#
# First make sure default does not error for a 1000 element array
# @TEST-EXEC: zeek -b -r $TRACES/redis/array-element-object-exhaustion.pcap %INPUT >output
# @TEST-EXEC: test ! -f analyzer_debug.log
#
# Now exceed the limit
# @TEST-EXEC: zeek -b -r $TRACES/redis/array-element-object-exhaustion.pcap Redis::max_aggregate_elements=500 %INPUT >output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=diff-canonifier-spicy btest-diff-cut -m analyzer_debug.log

@load base/protocols/redis
@load frameworks/analyzer/debug-logging

# Only want violations
redef Analyzer::DebugLogging::include_confirmations = F;
redef Analyzer::DebugLogging::include_disabling = F;
