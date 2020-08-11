# @TEST-EXEC: btest-bg-run zeekproc zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 45
# @TEST-EXEC: cat zeekproc/intel.log > output
# @TEST-EXEC: cat zeekproc/.stdout >> output
# @TEST-EXEC: btest-diff output

# @TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
1.2.3.4	Intel::ADDR	source1	this host is bad	http://some-data-distributor.com/1
192.168.0.0/16	Intel::SUBNET	source1	this network is bad	http://some-data-distributor.com/2
# @TEST-END-FILE

@load frameworks/intel/do_expire

redef exit_only_after_terminate = T;

redef Intel::read_files += { "../intel.dat" };
redef enum Intel::Where += { SOMEWHERE };

global runs = 0;
global entries_read = 0;
global start_time: time;
global expire_count = 0;
const intel_expiry = 9sec;
redef Intel::item_expiration = intel_expiry;
redef table_expire_interval = 0.2sec;

event do_it()
	{
	++runs;
	print fmt("-- Run %s --", runs);

	print "Seen: 1.2.3.4";
	Intel::seen([$host=1.2.3.4, $where=SOMEWHERE]);

	if ( runs == 4 )
		schedule 1sec { do_it() };
	else if ( runs > 4 )
		terminate();
	}

event Intel::match(s: Intel::Seen, items: set[Intel::Item])
	{
	print fmt("Match: %s", s$indicator);
	}

hook Intel::item_expired(indicator: string, indicator_type: Intel::Type,
                         metas: set[Intel::MetaData])
	{
	++expire_count;

	if ( expire_count == 2 )
		# Check that time of expiry indicates is approximately what's expected
		# after having been refreshed.
		print fmt("Expired: %s (took longer: %s)", indicator, (network_time() - start_time) > intel_expiry + 2sec);
	else
		print fmt("Expired: %s", indicator);

	event do_it();
	}

event refresh()
	{
	# Reinserting the indicator should reset the expiration
	local item = [
		$indicator="1.2.3.4",
		$indicator_type=Intel::ADDR,
		$meta=[
			$source="source2",
			$desc="this host is still bad",
			$url="http://some-data-distributor.com/2"]
		];
	Intel::insert(item);
	event do_it();
	}

event Intel::read_entry(desc: Input::EventDescription, tpe: Input::Event, item: Intel::Item)
	{
	++entries_read;

	if ( entries_read == 2 )
		{
		start_time = network_time();
		event do_it();
		schedule 3sec { refresh() };
		}
	}
