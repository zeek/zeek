# @TEST-EXEC-FAIL: zeek -r $TRACES/workshop_2011_browse.trace -f "kaputt" >>output 2>&1
# @TEST-EXEC-FAIL: test -e conn.log
# @TEST-EXEC: echo ---- >>output
# @TEST-EXEC: zeek -r $TRACES/workshop_2011_browse.trace  %INPUT >>output 2>&1
# @TEST-EXEC: test -e conn.log
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

redef enum PcapFilterID += { A };

event zeek_init()
	{
	if ( ! Pcap::precompile_pcap_filter(A, "kaputt, too") )
		print "error", Pcap::error();
	}


