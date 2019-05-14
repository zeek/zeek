
# @TEST-EXEC: btest-bg-run broproc zeek %INPUT
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: btest-diff broproc/intel.log

@TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
1.2.3.42	Intel::ADDR	source1	this host is just plain baaad	http://some-data-distributor.com/1234
10.0.0.1	Intel::ADDR	source1	this host is just plain baaad	http://some-data-distributor.com/1234
@TEST-END-FILE

redef exit_only_after_terminate = T;
redef Site::local_nets += { 10.0.0.0/8 };
redef Intel::read_files += { "../intel.dat" };
redef enum Intel::Where += { SOMEWHERE };

hook Intel::filter_item(item: Intel::Item)
	{
	if ( item$indicator_type == Intel::ADDR &&
		 Site::is_local_addr(to_addr(item$indicator)) )
		break;
	}

event do_it()
	{
	Intel::seen([$host=10.0.0.1,
	             $where=SOMEWHERE]);
	Intel::seen([$host=1.2.3.42,
	             $where=SOMEWHERE]);
	}

global log_lines = 0;
event Intel::log_intel(rec: Intel::Info)
	{
	++log_lines;
	if ( log_lines == 1 )
		terminate();
	}

event zeek_init() &priority=-10
	{
	schedule 1sec { do_it() };
	}
