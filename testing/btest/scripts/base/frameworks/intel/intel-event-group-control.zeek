# @TEST-EXEC: btest-bg-run zeekproc zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 15
# @TEST-EXEC: btest-diff zeekproc/intel.log
# @TEST-EXEC: cat zeekproc/.stdout > output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: cat zeekproc/.stderr > err
# @TEST-EXEC: btest-diff err

# @TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
1.2.3.4	Intel::ADDR	source1	this host is just plain baaad	http://some-data-distributor.com/1234
1.2.3.4	Intel::ADDR	source1	this host is just plain baaad	http://some-data-distributor.com/1234
192.168.1.1	Intel::ADDR	source1	this host is just plain baaad	http://some-data-distributor.com/1
e@mail.com	Intel::EMAIL	source1	Phishing email source	http://some-data-distributor.com/100000
# @TEST-END-FILE

@load policy/frameworks/intel/manage_groups

redef exit_only_after_terminate = T;
redef Intel::read_files += { "../intel.dat" };
redef enum Intel::Where += { SOMEWHERE };

event do_it() &group="Intel::EMAIL"
	{
	print "EMAIL: seen";
	Intel::seen([$indicator="e@mail.com", $indicator_type=Intel::EMAIL, $where=SOMEWHERE]);
	}

event do_it() &group="Intel::ADDR"
	{
	print "ADDR: seen";
	Intel::seen([$host=1.2.3.4, $where=SOMEWHERE]);
	}

event do_it() &group="Intel::URL"
	{
	print "URL: none";
	}

event do_it() &group="Intel::ADDR"
	{
	print "ADDR: remove";
	Intel::remove([$indicator="192.168.1.1", $indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
	}

global reads = 0;
event Intel::read_entry(desc: Input::EventDescription, tpe: Input::Event, item: Intel::Item)
	{
	++reads;
	print item;
	if ( reads == 4 )
		event do_it();
	}

global log_lines = 0;
event Intel::log_intel(rec: Intel::Info)
	{
	++log_lines;
	if ( log_lines == 2 )
		{
		event do_it();
		terminate();
		}
	}
