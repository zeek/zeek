# @TEST-SERIALIZE: comm

# @TEST-EXEC: cp intel1.dat intel.dat
# @TEST-EXEC: btest-bg-run broproc bro %INPUT
# @TEST-EXEC: sleep 2
# @TEST-EXEC: cp intel2.dat intel.dat
# @TEST-EXEC: sleep 2
# @TEST-EXEC: cp intel3.dat intel.dat
# @TEST-EXEC: btest-bg-wait 6
# @TEST-EXEC: cat broproc/intel.log > output
# @TEST-EXEC: cat broproc/notice.log >> output
# @TEST-EXEC: btest-diff output

# @TEST-START-FILE intel1.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url	meta.do_notice
1.2.3.4	Intel::ADDR	source1	this host is just plain baaad	http://some-data-distributor.com/1234	F
# @TEST-END-FILE

# @TEST-START-FILE intel2.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url	meta.do_notice
1.2.3.4	Intel::ADDR	source2	this host is just plain baaad	http://some-data-distributor.com/1234	F
4.3.2.1	Intel::ADDR	source2	this host might also be baaad	http://some-data-distributor.com/4321	F
# @TEST-END-FILE

# @TEST-START-FILE intel3.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url	meta.do_notice
1.2.3.4	Intel::ADDR	source2	this host is just plain baaad	http://some-data-distributor.com/1234	T
4.3.2.1	Intel::ADDR	source2	this host might also be baaad	http://some-data-distributor.com/4321	T
# @TEST-END-FILE

@load base/frameworks/communication # let network-time run
@load frameworks/intel/do_notice

redef exit_only_after_terminate = T;
redef Intel::read_files += { "../intel.dat" };
redef enum Intel::Where += { SOMEWHERE };

global runs = 0;
event do_it()
	{
	Intel::seen([$host=1.2.3.4,
	             $where=SOMEWHERE]);
	Intel::seen([$host=4.3.2.1,
	             $where=SOMEWHERE]);

	++runs;
	if ( runs < 3 )
		schedule 3sec { do_it() };
	}

global log_lines = 0;
event Intel::log_intel(rec: Intel::Info)
	{
	++log_lines;
	if ( log_lines == 5 )
		terminate();
	}

event bro_init() &priority=-10
	{
	schedule 1sec { do_it() };
	}
