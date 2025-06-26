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

# @TEST-START-FILE profiling-test1.zeek

@if ( T )
event new_connection(c: connection)
	{ print "new conn"; }
@endif
# @TEST-END-FILE

# @TEST-START-FILE profiling-test2.zeek
@if ( F )
@else
event new_connection(c: connection)
	{ print "new conn"; }
@endif
@ifdef ( Conn::Info )
event zeek_init() { print Conn::Info; }
@else
event zeek_init() { print "No Conn::Info"; }
@endif
@ifndef ( Conn::Info )
event zeek_init() { print "No Conn::Info"; }
@else
event zeek_init() { print Conn::Info; }
@endif
# @TEST-END-FILE
