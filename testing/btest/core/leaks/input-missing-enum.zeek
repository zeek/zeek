# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -m -b %INPUT
# @TEST-EXEC: btest-bg-wait 60

@TEST-START-FILE input.log
#fields	e	i
IdoNot::Exist	1
@TEST-END-FILE

redef exit_only_after_terminate = T;

module A;

type Idx: record {
	i: int;
};

type Val: record {
	e: Log::ID;
};

global etable: table[int] of Log::ID = table();

event zeek_init()
	{
	# first read in the old stuff into the table...
	Input::add_table([$source="../input.log", $name="enum", $idx=Idx, $val=Val, $destination=etable, $want_record=F]);
	}

event Input::end_of_data(name: string, source:string)
	{
	print "Table:";
	print etable;
	Input::remove("enum");
	terminate();
	}
