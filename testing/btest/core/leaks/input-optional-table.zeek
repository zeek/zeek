# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -m -b %INPUT
# @TEST-EXEC: btest-bg-wait 60

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	i	b	r.a	r.b	r.c	
#types	int	bool	string	string	string
1	T	a	b	c
2	T	a	b	c
3	F	ba	bb	bc
4	T	bb	bd	-
5	T	a	b	c
6	F	a	b	c
7	T	a	b	c
@TEST-END-FILE

redef exit_only_after_terminate = T;

global outfile: file;

redef InputAscii::empty_field = "EMPTY";

module A;

type Sub: record {
	a: string;
	aa: string &optional;
	b : string;
	bb: string &optional;
	c: string &optional;
	d: string &optional;
};

type Idx: record {
	i: int;
};

type Val: record {
	b: bool;
	notb: bool &optional;
	r: Sub;
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
