# @TEST-EXEC: cp intel1.dat intel.dat
# @TEST-EXEC: btest-bg-run zeekproc zeek %INPUT
# @TEST-EXEC: $SCRIPTS/wait-for-file zeekproc/got1 5 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: cp intel2.dat intel.dat
# @TEST-EXEC: $SCRIPTS/wait-for-file zeekproc/got2 5 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: cp intel3.dat intel.dat
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: cat zeekproc/intel.log > output
# @TEST-EXEC: cat zeekproc/notice.log >> output
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

@load frameworks/intel/do_notice

redef exit_only_after_terminate = T;
redef Intel::read_files += { "../intel.dat" };
redef enum Intel::Where += { SOMEWHERE };

global runs = 0;
global entries_read = 0;

event do_it()
	{
	Intel::seen([$host=1.2.3.4,
	             $where=SOMEWHERE]);
	Intel::seen([$host=4.3.2.1,
	             $where=SOMEWHERE]);

	++runs;

	if ( runs == 1 )
		system("touch got1");
	if ( runs == 2 )
		system("touch got2");
	}

global log_lines = 0;
event Intel::log_intel(rec: Intel::Info)
	{
	++log_lines;
	if ( log_lines == 5 )
		terminate();
	}

module Intel;

event Intel::read_entry(desc: Input::EventDescription, tpe: Input::Event, item: Intel::Item)
	{
	++entries_read;
	print entries_read;

	if ( entries_read == 1 )
		event do_it();
	else if ( entries_read == 3 )
		event do_it();
	else if ( entries_read == 5 )
		event do_it();
	}
