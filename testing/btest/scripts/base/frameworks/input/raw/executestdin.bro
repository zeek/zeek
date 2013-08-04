# @TEST-EXEC: btest-bg-run bro bro -b %INPUT
# @TEST-EXEC: btest-bg-wait -k 5
# @TEST-EXEC: btest-diff test.txt
# @TEST-EXEC: btest-diff out

redef exit_only_after_terminate = T;
@load base/frameworks/communication  # let network-time run. otherwise there are no heartbeats...

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
	if ( try == 2 )
		{
		Input::remove("input2");
		close(outfile);
		terminate();
		}
	}

event bro_init()
	{
	local config_strings: table[string] of string = {
		["stdin"] = "hello\nthere\1\2\3\4\5\1\2\3yay"
		#["stdin"] = "yay"
	};

	try = 0;
	outfile = open("../out");
	Input::add_event([$source="cat > ../test.txt |", $reader=Input::READER_RAW, $mode=Input::STREAM, $name="input", $fields=Val, $ev=line, $want_record=F, $config=config_strings]);
	Input::add_event([$source="cat |", $reader=Input::READER_RAW, $mode=Input::STREAM, $name="input2", $fields=Val, $ev=line, $want_record=F, $config=config_strings]);
	}
