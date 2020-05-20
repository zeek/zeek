# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: grep -v "already queued for removal" .stderr > out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff out

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

module A;

type Idx: record {
	i: int;
};

type Val: record {
	p: pattern;
};

global pats: table[int] of Val = table();

event zeek_init()
	{
	Input::add_table([$source="input.log", $name="pats", $idx=Idx, $val=Val, $destination=pats]);
	}
