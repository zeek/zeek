# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
sdfkh:KH;fdkncv;ISEUp34:Fkdj;YVpIODhfDF
DSF"DFKJ"SDFKLh304yrsdkfj@#(*U$34jfDJup3UF
q3r3057fdf
sdfs\d

dfsdf
sdf
3rw43wRRERLlL#RWERERERE.
@TEST-END-FILE

redef exit_only_after_terminate = T;

global outfile: file;
global try: count;

module A;

type Val: record {
	s: string;
};

event line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	print outfile, description;
	print outfile, tpe;
	print outfile, s;
	try = try + 1;
	if ( try == 8 )
		{
		Input::remove("input");
		close(outfile);
		terminate();
		}
	}

event zeek_init()
	{
	try = 0;
	outfile = open("../out");
	Input::add_event([$source="../input.log", $reader=Input::READER_RAW, $mode=Input::STREAM, $name="input", $fields=Val, $ev=line, $want_record=F]);
	}
