# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
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

redef exit_only_after_terminate = T;

global outfile: file;

module A;

type Val: record {
	i: int;
	b: bool;
	s: string &default="leer";
};

event line(description: Input::EventDescription, tpe: Input::Event, val: Val)
	{
	print outfile, val;
	}

event zeek_init()
	{
	outfile = open("../out");
	Input::add_event([$source="../input.log", $name="input", $fields=Val, $ev=line, $want_record=T]);
	}

event Input::end_of_data(name: string, source:string)
	{
	print outfile, "End-of-data";
	Input::remove("input");
	close(outfile);
	terminate();
	}
