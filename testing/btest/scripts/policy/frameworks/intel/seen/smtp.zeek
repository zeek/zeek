# @TEST-EXEC: zeek -r $TRACES/smtp-multi-addr.pcap %INPUT
# @TEST-EXEC: btest-diff intel.log

@TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
jan.grashoefer@gmail.com	Intel::EMAIL	source1	test entry	http://some-data-distributor.com/100000
jan.grashoefer@cern.ch	Intel::EMAIL	source1	test entry	http://some-data-distributor.com/100000
jan.grashofer@cern.ch	Intel::EMAIL	source1	test entry	http://some-data-distributor.com/100000
addr-spec@example.com	Intel::EMAIL	source1	test entry	http://some-data-distributor.com/100000
angle-addr@example.com	Intel::EMAIL	source1	test entry	http://some-data-distributor.com/100000
name-addr@example.com	Intel::EMAIL	source1	test entry	http://some-data-distributor.com/100000
@TEST-END-FILE

@load base/frameworks/intel
@load frameworks/intel/seen

redef Intel::read_files += { "intel.dat" };

event zeek_init()
	{
	suspend_processing();
	}

event Input::end_of_data(name: string, source: string)
	{
	continue_processing();
	}

event SMTP::log_smtp(rec: SMTP::Info)
	{
	for ( adr in rec$to )
		{
		print fmt("Addr: '%s'", adr);
		}
	}
