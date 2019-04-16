# @TEST-EXEC-FAIL: bro -i NO_SUCH_INTERFACE 2>&1  >>output 2>&1
# @TEST-EXEC: cat output | sed 's/(.*)//g' >output2
# @TEST-EXEC-FAIL: bro -r NO_SUCH_TRACE 2>&1 >>output2 2>&1
# @TEST-EXEC: btest-diff output2

redef enum PcapFilterID += { A };

event bro_init()
	{
	if ( ! Pcap::precompile_pcap_filter(A, "kaputt, too") )
		print "error", Pcap::error();
	}


