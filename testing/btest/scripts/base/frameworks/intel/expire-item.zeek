# @TEST-EXEC: btest-bg-run broproc zeek %INPUT
# @TEST-EXEC: btest-bg-wait -k 21
# @TEST-EXEC: cat broproc/intel.log > output
# @TEST-EXEC: cat broproc/.stdout >> output
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
redef Intel::item_expiration = 9sec;
redef table_expire_interval = 3sec;

global runs = 0;
event do_it()
	{
	++runs;
	print fmt("-- Run %s --", runs);

	print "Trigger: 1.2.3.4";
	Intel::seen([$host=1.2.3.4,
	             $where=SOMEWHERE]);

	if ( runs == 2 )
		{
		# Reinserting the indicator should reset the expiration
		print "Reinsert: 1.2.3.4";
		local item = [
			$indicator="1.2.3.4",
			$indicator_type=Intel::ADDR,
			$meta=[
				$source="source2",
				$desc="this host is still bad",
				$url="http://some-data-distributor.com/2"]
			];
		Intel::insert(item);
		}

	if ( runs < 6 )
		schedule 3sec { do_it() };
	else
		terminate();
	}

event Intel::match(s: Intel::Seen, items: set[Intel::Item])
	{
	print fmt("Seen: %s", s$indicator);
	}

hook Intel::item_expired(indicator: string, indicator_type: Intel::Type,
	metas: set[Intel::MetaData])
	{
	print fmt("Expired: %s", indicator);
	}

event zeek_init() &priority=-10
	{
	schedule 1.5sec { do_it() };
	}
