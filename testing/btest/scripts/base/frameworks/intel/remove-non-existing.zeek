# @TEST-EXEC: btest-bg-run broproc zeek %INPUT
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: cat broproc/reporter.log > output
# @TEST-EXEC: cat broproc/.stdout >> output
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-abspath | $SCRIPTS/diff-remove-timestamps" btest-diff output

# @TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
192.168.1.1	Intel::ADDR	source1	this host is just plain baaad	http://some-data-distributor.com/1
# @TEST-END-FILE

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

event zeek_init() &priority=-10
	{
	schedule 1sec { do_it() };
	}
