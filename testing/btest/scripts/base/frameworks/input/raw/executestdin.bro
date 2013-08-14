# @TEST-EXEC: btest-bg-run bro bro -b %INPUT
# @TEST-EXEC: btest-bg-wait 15
# @TEST-EXEC: btest-diff test.txt
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff out

redef exit_only_after_terminate = T;
@load base/frameworks/communication  # let network-time run. otherwise there are no heartbeats...

global outfile: file;
global processes_finished: count = 0;
global n: count = 0;
global total_processes: count = 0;

global config_strings: table[string] of string = {
	["stdin"] = "hello\nthere\1\2\3\4\5\1\2\3yay"
};

module A;

type Val: record {
	s: string;
};

event line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	print outfile, tpe, description$source, description$name;
	print outfile, s;
	}

event InputRaw::process_finished(name: string, source:string, exit_code:count, signal_exit:bool)
	{
	print "process_finished", name, source;
	Input::remove(name);
	++processes_finished;
	if ( processes_finished == total_processes )
		{
		close(outfile);
		terminate();
		}
	}

function more_input(name_prefix: string)
	{
	local name = fmt("%s%d", name_prefix, n);
	config_strings["stdin"] += fmt("%d", n);
	++n;
	++total_processes;
	Input::add_event([$source="cat |",
	                  $reader=Input::READER_RAW, $mode=Input::STREAM,
	                  $name=name, $fields=Val, $ev=line, $want_record=F,
	                  $config=config_strings]);
	}

event bro_init()
	{
	outfile = open("../out");
	++total_processes;

	Input::add_event([$source="cat > ../test.txt |",
	                  $reader=Input::READER_RAW, $mode=Input::STREAM,
	                  $name="input", $fields=Val, $ev=line, $want_record=F,
	                  $config=config_strings]);
	more_input("input");
	more_input("input");
	more_input("input");
	more_input("input");
	more_input("input");
	}
