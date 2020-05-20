# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff out

redef exit_only_after_terminate = T;

redef InputAscii::separator = "|";
redef InputAscii::set_separator = ",";
redef InputAscii::empty_field = "(empty)";
redef InputAscii::unset_field = "-";

@TEST-START-FILE input.log
#separator |
#set_separator|,
#empty_field|(empty)
#unset_field|-
#path|ssh
#open|2012-07-20-01-49-19
#fields|data|data2
#types|string|string
abc\x0a\xffdef|DATA2
abc\x7c\xffdef|DATA2
abc\xff\x7cdef|DATA2
#end|2012-07-20-01-49-19
@TEST-END-FILE

global outfile: file;
global try: count;

type Val: record {
		data: string;
		data2: string;
};

event line(description: Input::EventDescription, tpe: Input::Event, a: string, b: string)
	{
	print outfile, a;
	print outfile, b;
	try = try + 1;
	if ( try == 3 )
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
	Input::add_event([$source="../input.log", $name="input", $fields=Val, $ev=line, $want_record=F]);
	}
