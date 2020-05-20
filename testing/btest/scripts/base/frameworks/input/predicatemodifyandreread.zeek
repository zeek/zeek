# @TEST-EXEC: mv input1.log input.log
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got1 5 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: mv input2.log input.log
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got2 5 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: mv input3.log input.log
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got3 5 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: mv input4.log input.log
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/got4 5 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: mv input5.log input.log
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff out
#

@TEST-START-FILE input1.log
#separator \x09
#path	ssh
#fields	i	b	s	ss
#types	int	bool	string	string
1	T	test1	idx1
2	T	test2	idx2
@TEST-END-FILE

@TEST-START-FILE input2.log
#separator \x09
#path	ssh
#fields	i	b	s	ss
#types	int	bool	string	string
1	F	test1	idx1
2	T	test2	idx2
@TEST-END-FILE

@TEST-START-FILE input3.log
#separator \x09
#path	ssh
#fields	i	b	s	ss
#types	int	bool	string	string
1	F	test1	idx1
2	F	test2	idx2
@TEST-END-FILE

@TEST-START-FILE input4.log
#separator \x09
#path	ssh
#fields	i	b	s	ss
#types	int	bool	string	string
2	F	test2	idx2
@TEST-END-FILE

@TEST-START-FILE input5.log
#separator \x09
#path	ssh
#fields	i	b	s	ss
#types	int	bool	string	string
1	T	test1	idx1
@TEST-END-FILE

redef exit_only_after_terminate = T;

redef InputAscii::empty_field = "EMPTY";

module A;

type Idx: record {
	i: int;
	ss: string;
};

type Val: record {
	b: bool;
	s: string;
};

global servers: table[int, string] of Val = table();
global outfile: file;
global try: count;

event zeek_init()
	{
	try = 0;
	outfile = open("../out");
	# first read in the old stuff into the table...
	Input::add_table([$source="../input.log", $name="input", $idx=Idx, $val=Val, $destination=servers, $mode=Input::REREAD,
				$pred(typ: Input::Event, left: Idx, right: Val) = { 
				if ( left$i == 1 )
					right$s = "testmodified";
				if ( left$i == 2 )
					left$ss = "idxmodified";
				return T; 
				}
				]);
	}

event Input::end_of_data(name: string, source: string)
	{
	try = try + 1;
	print outfile, fmt("Update_finished for %s, try %d", name, try);
	print outfile, servers;

	if ( try == 1 )
		system("touch got1");
	else if ( try == 2 )
		system("touch got2");
	else if ( try == 3 )
		system("touch got3");
	else if ( try == 4 )
		system("touch got4");
	if ( try == 5 )
		{
		close(outfile);
		Input::remove("input");
		terminate();
		}
	}
