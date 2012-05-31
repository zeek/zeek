#
# @TEST-EXEC: cp input1.log input.log
# @TEST-EXEC: btest-bg-run bro bro -b %INPUT 
# @TEST-EXEC: sleep 3
# @TEST-EXEC: cat input2.log >> input.log
# @TEST-EXEC: sleep 3
# @TEST-EXEC: cat input3.log >> input.log
# @TEST-EXEC: btest-bg-wait -k 3
# @TEST-EXEC: btest-diff out

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

@load frameworks/communication/listen

module A;

type Val: record {
	s: string;
};

global try: count;
global outfile: file;

event line(description: Input::EventDescription, tpe: Input::Event, s: string) {
	print outfile, description;
	print outfile, tpe;
	print outfile, s;
	
	if ( try == 3 ) {
		print outfile, "done";
		close(outfile);
		Input::remove("input");
	}
}

event bro_init()
{
	outfile = open ("../out");
	try = 0;
	Input::add_event([$source="../input.log", $reader=Input::READER_RAW, $mode=Input::STREAM, $name="input", $fields=Val, $ev=line]);
}
