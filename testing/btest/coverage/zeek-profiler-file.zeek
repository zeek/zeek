# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"
#
# @TEST-EXEC: ZEEK_PROFILER_FILE=cov.txt zeek -b -r $TRACES/http/get.trace profiling-test1.zeek
# @TEST-EXEC: grep profiling-test1.zeek cov.txt > step1.out
# @TEST-EXEC: btest-diff step1.out

# @TEST-EXEC: ZEEK_PROFILER_FILE=cov.txt zeek -b -r $TRACES/http/get.trace profiling-test1.zeek
# @TEST-EXEC: grep profiling-test1.zeek cov.txt > step2.out
# @TEST-EXEC: btest-diff step2.out

# @TEST-EXEC: ZEEK_PROFILER_FILE=cov.txt zeek -r $TRACES/http/get.trace profiling-test2.zeek
# @TEST-EXEC: grep profiling-test cov.txt > step3.out
# @TEST-EXEC: btest-diff step3.out

@TEST-START-FILE profiling-test1.zeek
event new_connection(c: connection)
	{ print "new conn"; }
@TEST-END-FILE

@TEST-START-FILE profiling-test2.zeek
event new_connection(c: connection)
	{ print "new conn"; }
@TEST-END-FILE
