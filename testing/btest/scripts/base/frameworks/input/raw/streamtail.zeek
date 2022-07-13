# Test "tail -F" functionality (record version)

# Start without the file
# @TEST-EXEC: rm -f input.log
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: sleep 1

# Create the file
# @TEST-EXEC: cp input1.log input.log
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got1 5 || (btest-bg-wait -k 1 && false)

# Append to the file
# @TEST-EXEC: cat input2.log >> input.log
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got2 5 || (btest-bg-wait -k 1 && false)

# Move onto the file
# @TEST-EXEC: cp input3.log _input.log
# @TEST-EXEC: mv _input.log input.log

# Done!
# @TEST-EXEC: btest-bg-wait 60
# @TEST-EXEC: btest-diff out

redef exit_only_after_terminate = T;

@TEST-START-FILE input1.log
sdfkh:KH;fdkncv;ISEUp34:Fkdj;YVpIODhfDF
@TEST-END-FILE

@TEST-START-FILE input2.log
DSF"DFKJ"SDFKLh304yrsdkfj@#(*U$34jfDJup3UF
@TEST-END-FILE

@TEST-START-FILE input3.log
3rw43wRRERLlL#RWERERERE.
@TEST-END-FILE

module A;

type lineVal: record {
	s: string;
};

global try: count;
global outfile: file;

event line(description: Input::EventDescription, tpe: Input::Event, s: lineVal)
	{
	print outfile, description$source, description$reader, description$mode, description$name;
	print outfile, tpe;
	print outfile, s$s;

	try = try + 1;

	if ( try == 1 )
		system("touch got1");
	else if ( try == 2 )
		system("touch got2");
	else if ( try == 3 )
		{
		close(outfile);
		Input::remove("input");
		terminate();
		}
	}

event zeek_init()
	{
	outfile = open("../out");
	try = 0;
	Input::add_event([$source="../input.log",
	    $reader=Input::READER_RAW, $mode=Input::STREAM, $name="input",
	    $fields=lineVal, $ev=line]);
	}
