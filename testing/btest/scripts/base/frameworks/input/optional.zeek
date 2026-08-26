# @TEST-DOC: Test &optional fields in the input framework, both simple types and records.
#
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff zeek/.stderr

# @TEST-START-FILE input.log
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
# @TEST-END-FILE

redef exit_only_after_terminate = T;

global outfile: file;

redef InputAscii::empty_field = "EMPTY";

module A;

type Idx: record {
	i: int;
};

type Val: record {
	b: bool;
	notb: bool &optional;
};

global servers: table[int] of Val = table();

event zeek_init()
	{
	outfile = open("../out");
	# first read in the old stuff into the table...
	Input::add_table([$source="../input.log", $name="input", $idx=Idx, $val=Val, $destination=servers,
	                  $pred(typ: Input::Event, left: Idx, right: Val) = { right$notb = !right$b; return T; }
	                 ]);
	}

event Input::end_of_data(name: string, source: string)
	{
	print outfile, servers;
	Input::remove("input");
	close(outfile);
	terminate();
	}

# @TEST-START-NEXT
#
# Test table input with an optional record in the input file, absent in part of
# fully, in some input lines.

# @TEST-START-FILE input-sub.log
#separator \x09
#path	ssh
#fields	i	b	sub.s	sub.c	sub.deep.a
#types	int	bool	string	count	addr
1	T	one	11	10.0.0.1
2	T	-	-	-
3	F	three	-	10.0.0.3
# @TEST-END-FILE

redef exit_only_after_terminate = T;

global outfile: file;

module A;

type Idx: record {
	i: int;
};

type Deep: record {
	a: addr;
};

type Sub: record {
	s: string;
	c: count;
	deep: Deep;
};

type Val: record {
	b: bool;
	sub: Sub &optional;
};

global servers: table[int] of Val = table();

event zeek_init()
	{
	outfile = open("../out");
	Input::add_table([$source="../input-sub.log", $name="input", $idx=Idx, $val=Val, $destination=servers]);
	}

event Input::end_of_data(name: string, source: string)
	{
	print outfile, "all sub columns set", servers[1];
	print outfile, "all sub columns unset", servers[2];
	print outfile, "some sub columns unset", servers[3];
	Input::remove("input");
	close(outfile);
	terminate();
	}

# @TEST-START-NEXT
#
# Test an optional record in the input file, wholly absent in the input file at
# the tail end of the line.

# @TEST-START-FILE input-nosub.log
#separator \x09
#path	ssh
#fields	i	b
#types	int	bool
1	T
# @TEST-END-FILE

redef exit_only_after_terminate = T;

global outfile: file;

module A;

type Idx: record {
	i: int;
};

type Deep: record {
	a: addr;
};

type Sub: record {
	s: string;
	c: count;
	deep: Deep;
};

type Val: record {
	b: bool;
	sub: Sub &optional;
};

global servers: table[int] of Val = table();

event zeek_init()
	{
	outfile = open("../out");
	Input::add_table([$source="../input-nosub.log", $name="input", $idx=Idx, $val=Val, $destination=servers]);
	}

event Input::end_of_data(name: string, source: string)
	{
	print outfile, "no sub columns in input", servers[1];
	Input::remove("input");
	close(outfile);
	terminate();
	}

# @TEST-START-NEXT
#
# Test event generation with an optional record in the input file, absent in
# part of fully, in some input lines.

redef exit_only_after_terminate = T;

global outfile: file;

module A;

type Deep: record {
	a: addr;
};

type Sub: record {
	s: string;
	deep: Deep;
};

type Val: record {
	b: bool;
	sub: Sub &optional;
};

event line(description: Input::EventDescription, tpe: Input::Event, v: Val)
	{
	print outfile, v;
	}

event zeek_init()
	{
	outfile = open("../out");
	Input::add_event([$source="../input-sub.log", $name="input", $fields=Val, $ev=line, $want_record=T]);
	}

event Input::end_of_data(name: string, source: string)
	{
	Input::remove("input");
	close(outfile);
	terminate();
	}

# @TEST-START-NEXT
#
# Test robust handling of erroneously missing, non-optional fields in the input:
# these should be skipped.

redef exit_only_after_terminate = T;

global outfile: file;

module A;

type Idx: record {
	i: int;
};

type Sub: record {
	s: string;
};

type Val: record {
	b: bool;
	sub: Sub;
};

global servers: table[int] of Val = table();

event zeek_init()
	{
	outfile = open("../out");
	Input::add_table([$source="../input-sub.log", $name="input", $idx=Idx, $val=Val, $destination=servers]);
	}

event Input::end_of_data(name: string, source: string)
	{
	print outfile, servers[1], servers[3], 2 !in servers;
	Input::remove("input");
	close(outfile);
	terminate();
	}
