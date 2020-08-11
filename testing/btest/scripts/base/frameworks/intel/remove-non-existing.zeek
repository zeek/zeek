# @TEST-EXEC: btest-bg-run zeekproc zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: cat zeekproc/reporter.log > output
# @TEST-EXEC: cat zeekproc/.stdout >> output
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath | $SCRIPTS/diff-remove-timestamps" btest-diff output

# @TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
192.168.1.1	Intel::ADDR	source1	this host is just plain baaad	http://some-data-distributor.com/1
# @TEST-END-FILE

@load base/frameworks/intel
@load base/frameworks/reporter

redef exit_only_after_terminate = T;

redef Intel::read_files += { "../intel.dat" };
redef enum Intel::Where += { SOMEWHERE };

event do_it()
	{
	# not existing meta data:
	Intel::remove([$indicator="192.168.1.1", $indicator_type=Intel::ADDR, $meta=[$source="source23"]]);
	# existing:
	Intel::remove([$indicator="192.168.1.1", $indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
	# not existing item:
	Intel::remove([$indicator="192.168.1.1", $indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
	terminate();
	}

event Intel::read_entry(desc: Input::EventDescription, tpe: Input::Event, item: Intel::Item)
	{
	event do_it();
	}
