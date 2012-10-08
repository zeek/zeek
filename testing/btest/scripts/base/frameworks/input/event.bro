# (uses listen.bro just to ensure input sources are more reliably fully-read).
# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run bro bro -b %INPUT
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	i	b	
#types	int	bool
1	T
2	T
3	F
4	F
5	F
6	F
7	T
@TEST-END-FILE

@load frameworks/communication/listen

global outfile: file;
global try: count;

module A;

type Val: record {
	i: int;
	b: bool;
};

event line(description: Input::EventDescription, tpe: Input::Event, i: int, b: bool)
	{
	print outfile, description;
	print outfile, tpe;
	print outfile, i;
	print outfile, b;
	try = try + 1;
	if ( try == 7 )
		{
		close(outfile);
		terminate();
		}
	}

event bro_init()
	{
	try = 0;
	outfile = open("../out");
	Input::add_event([$source="../input.log", $name="input", $fields=Val, $ev=line, $want_record=F]);
	Input::remove("input");
	}
