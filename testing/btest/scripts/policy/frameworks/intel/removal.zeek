
# @TEST-EXEC: btest-bg-run zeekproc zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff zeekproc/intel.log

@TEST-START-FILE intel.dat
#fields	indicator	indicator_type	meta.source	meta.remove
10.0.0.1	Intel::ADDR	source1	T
10.0.0.2	Intel::ADDR	source1	F
@TEST-END-FILE

@load frameworks/intel/removal

redef exit_only_after_terminate = T;
redef Intel::read_files += { "../intel.dat" };
redef enum Intel::Where += { SOMEWHERE };

hook Intel::filter_item(item: Intel::Item)
	{
	if ( item$indicator_type == Intel::ADDR &&
		! Site::is_local_addr(to_addr(item$indicator)) )
		break;
	}

global log_lines = 0;
event Intel::log_intel(rec: Intel::Info)
	{
	++log_lines;
	if ( log_lines == 3 )
		terminate();
	}

global entries_read = 0;
event Intel::read_entry(desc: Input::EventDescription, tpe: Input::Event, item: Intel::Item)
	{
	++entries_read;

	if ( entries_read == 2 )
		{
		Intel::seen([$host=10.0.0.1, $where=SOMEWHERE]);
		Intel::seen([$host=10.0.0.2, $where=SOMEWHERE]);
		}
	}

event zeek_init()
	{
	Intel::insert([$indicator="10.0.0.1", $indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
	Intel::insert([$indicator="10.0.0.2", $indicator_type=Intel::ADDR, $meta=[$source="source1"]]);
	Intel::seen([$host=10.0.0.1, $where=SOMEWHERE]);
	Intel::seen([$host=10.0.0.2, $where=SOMEWHERE]);
	}
