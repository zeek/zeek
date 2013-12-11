# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: bro  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: cp input1.log input.log
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run bro bro -m -b %INPUT 
# @TEST-EXEC: sleep 5
# @TEST-EXEC: cat input2.log >> input.log
# @TEST-EXEC: sleep 5
# @TEST-EXEC: cat input3.log >> input.log
# @TEST-EXEC: btest-bg-wait 10

redef exit_only_after_terminate = T;

@TEST-START-FILE input1.log
sdfkh:KH;fdkncv;ISEUp34:Fkdj;YVpIODhfDF
@TEST-END-FILE

@TEST-START-FILE input2.log
DSF"DFKJ"SDFKLh304yrsdkfj@#(*U$34jfDJup3UF
q3r3057fdf
@TEST-END-FILE

@TEST-START-FILE input3.log
sdfs\d

dfsdf
sdf
3rw43wRRERLlL#RWERERERE.
@TEST-END-FILE

@load base/frameworks/communication  # let network-time run

module A;

type Val: record {
	s: string;
};

global try: count;
global outfile: file;

event line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	print outfile, description$name;
	print outfile, tpe;
	print outfile, s;

	try = try + 1;
	if ( try == 16 )
		{
		print outfile, "done";
		close(outfile);
		Input::remove("input");
		Input::remove("tail");
		terminate();
		}
	}

event bro_init()
	{
	outfile = open("../out");
	try = 0;
	Input::add_event([$source="../input.log", $reader=Input::READER_RAW, $mode=Input::STREAM, $name="input", $fields=Val, $ev=line, $want_record=F]);
	Input::add_event([$source="tail -f ../input.log |", $reader=Input::READER_RAW, $mode=Input::STREAM, $name="tail", $fields=Val, $ev=line, $want_record=F]);
	}
