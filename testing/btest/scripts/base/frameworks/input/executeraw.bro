# (uses listen.bro just to ensure input sources are more reliably fully-read).
# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run bro bro -b %INPUT
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: cat out.tmp | sed 's/^ *//g' >out
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

@load frameworks/communication/listen

global outfile: file;

type Val: record {
	s: string;
};

event line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	print outfile, description;
	print outfile, tpe;
	print outfile, s;
	close(outfile);
	terminate();
	}

event bro_init()
	{
	outfile = open("../out.tmp");
	Input::add_event([$source="wc -l ../input.log |", $reader=Input::READER_RAW, $name="input", $fields=Val, $ev=line, $want_record=F]);
	Input::remove("input");
	}
