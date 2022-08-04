# Due to the instability of the output from libpcap when it comes to errors when compiling
# filters, we can't rely on a fixed baseline here to diff against. Instead, just do some
# greps to validate that we got a syntax error in the output with the string that we passed
# as a filter.

# Don't run for C++ scripts, since first invocation doesn't use the input
# and hence leads to complaints that there are no scripts.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
#
# @TEST-EXEC-FAIL: zeek -r $TRACES/workshop_2011_browse.trace -f "kaputt" >output 2>&1
# @TEST-EXEC-FAIL: test -e conn.log
# @TEST-EXEC: grep "kaputt" output | grep -q "syntax error"
# @TEST-EXEC: zeek -r $TRACES/workshop_2011_browse.trace  %INPUT >output 2>&1
# @TEST-EXEC: test -e conn.log
# @TEST-EXEC: grep "kaputt, too" output | grep -q "syntax error"

redef enum PcapFilterID += { A };

event zeek_init()
	{
	if ( ! Pcap::precompile_pcap_filter(A, "kaputt, too") )
		print "error", Pcap::error();
	}
