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

@TEST-START-FILE input2.log
Beginning of input2.log
3rw43wRRERLlL#RWERERERE.
game over
@TEST-END-FILE

redef Threading::heartbeat_interval = 100msec;
redef exit_only_after_terminate = T;

global outfile: file;

module A;

type Val: record {
	s: string;
};

global end_of_datas = 0;

event Input::end_of_data(name: string, source: string)
	{
	++end_of_datas;
	if ( end_of_datas > 1 )
		return;

	print outfile, "end_of_data, updating input.log";
	# This should be recognized by the raw reader as file update (inode change)
	# and the new file is reread.
	system("mv ../input2.log ../input.log");
	}

global lines = 0;

event A::line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	++lines;
	print outfile, lines, tpe, s, |s|;
	if ( s == "game over" )
		{
		Input::remove("input");
		close(outfile);
		terminate();
		}
	}

event zeek_init()
	{
	outfile = open("../out");
	Input::add_event([$source="../input.log", $reader=Input::READER_RAW, $mode=Input::REREAD, $name="input", $fields=Val, $ev=A::line, $want_record=F]);
	}
