# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -b -m -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-bg-wait 60

@load base/frameworks/input

redef exit_only_after_terminate = T;

global c: count = 0;


type OneLine: record {
	s: string;
};

event line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	print "1", "Line";
	}

event InputRaw::process_finished(name: string, source:string, exit_code:count, signal_exit:bool)
	{
	Input::remove(name);
	print "2", name;
	}

function run(): count
	{
	Input::add_event([$name=unique_id(""),
	                  $source=fmt("%s |", "date"),
	                  $reader=Input::READER_RAW,
	                  $mode=Input::STREAM,
	                  $fields=OneLine,
	                  $ev=line,
	                  $want_record=F]);

	return 1;
	}


event do()
       {
       run();
    	}

event do_term() {
	terminate();
}

event zeek_init() {
	schedule 1sec { 
	 do() 
	};
	schedule 3sec { 
	 do_term() 
	};
}

