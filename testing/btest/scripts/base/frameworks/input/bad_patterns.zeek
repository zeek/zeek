# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stderr

@TEST-START-FILE input.log
#separator \x09
#fields	i	p
#types	count	pattern
1	/d/og/
2	/cat/sss
3	/foo|bar
4	this is not a pattern
5	/5
@TEST-END-FILE

redef exit_only_after_terminate = T;

module A;

type Idx: record {
	i: int;
};

type Val: record {
	p: pattern;
};

event kill_me()
	{
	terminate();
	}

global pats: table[int] of Val = table();

event zeek_init()
	{
	Input::add_table([$source="input.log", $name="pats", $idx=Idx, $val=Val, $destination=pats]);
	schedule 10msec { kill_me() };
	}
