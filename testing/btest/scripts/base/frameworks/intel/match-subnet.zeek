# @TEST-EXEC: btest-bg-run zeekproc zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 15
# @TEST-EXEC: cat zeekproc/intel.log > output
# @TEST-EXEC: cat zeekproc/.stdout >> output
# @TEST-EXEC: btest-diff output

# @TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
192.168.1.1	Intel::ADDR	source1	this host is just plain baaad	http://some-data-distributor.com/1
192.168.2.0/24	Intel::SUBNET	source1	this subnetwork is just plain baaad	http://some-data-distributor.com/2
192.168.142.1	Intel::ADDR	source1	this host is just plain baaad	http://some-data-distributor.com/3
192.168.142.0/24	Intel::SUBNET	source1	this subnetwork is baaad	http://some-data-distributor.com/4
192.168.142.0/26	Intel::SUBNET	source1	this subnetwork is inside	http://some-data-distributor.com/4
192.168.128.0/18	Intel::SUBNET	source1	this subnetwork might be baaad	http://some-data-distributor.com/5
# @TEST-END-FILE

@load base/frameworks/intel

redef exit_only_after_terminate = T;

redef Intel::read_files += { "../intel.dat" };
redef enum Intel::Where += { SOMEWHERE };

event do_it()
	{
	Intel::seen([$host=192.168.1.1,
	             $where=SOMEWHERE]);
	Intel::seen([$host=192.168.2.1,
	             $where=SOMEWHERE]);
	Intel::seen([$host=192.168.142.1,
	             $where=SOMEWHERE]);
	}

global read = 0;
event Intel::read_entry(desc: Input::EventDescription, tpe: Input::Event, item: Intel::Item)
	{
	++read;

	if ( read == 6 )
		event do_it();
	}

global log_lines = 0;
event Intel::log_intel(rec: Intel::Info)
	{
	++log_lines;
	if ( log_lines == 2 )
		terminate();
	}

event Intel::match(s: Intel::Seen, items: set[Intel::Item])
	{
	print "";
	print fmt("Seen: %s", s);
	for ( item in items )
		print fmt("Item: %s", item);
	}
