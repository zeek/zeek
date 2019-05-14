# @TEST-EXEC: ${DIST}/aux/bro-aux/plugin-support/init-plugin  -u . Demo Foo
# @TEST-EXEC: cp -r %DIR/reader-plugin/* .
# @TEST-EXEC: ./configure --bro-dist=${DIST} && make
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` zeek -NN Demo::Foo >>output
# @TEST-EXEC: echo === >>output
# @TEST-EXEC: BRO_PLUGIN_PATH=`pwd` btest-bg-run zeek zeek %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff out

redef exit_only_after_terminate = T;

global outfile: file;
global try: count;

module A;

type Val: record {
	s: string;
};

event line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	print outfile, tpe;
	print outfile, s;
	try = try + 1;
	if ( try == 5 )
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
	Input::add_event([$source="../input.log", $reader=Input::READER_FOO, $mode=Input::STREAM, $name="input", $fields=Val, $ev=line, $want_record=F]);
	}
