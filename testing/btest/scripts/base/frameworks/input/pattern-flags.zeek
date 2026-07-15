# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stderr

redef exit_only_after_terminate = T;

# @TEST-START-FILE input.log
#separator \x09
#fields	p	v
#types	pattern	string
/dog/i	case-insensitive
/c.t/s	single-line
/foo.|bar/is	both-flags
/plain/	no-flags
/dup/isis	invalid-dup-flags
/other/isg	invalid-bad-flag
# @TEST-END-FILE

module A;

type Idx: record {
	p: pattern;
};

type Val: record {
	v: string;
};

global pats: table[pattern] of Val = table();

event zeek_init()
	{
	Input::add_table([$source="input.log", $name="pats", $idx=Idx, $val=Val, $destination=pats]);
	}

event Input::end_of_data(name: string, source:string)
	{
	# Only valid patterns should be loaded (4 of 6 entries).
	assert |pats| == 4;

	# /dog/i - case insensitive
	assert "DOG" in pats;
	assert "dog" in pats;
	assert "Dog" in pats;

	# /c.t/s - single-line (. matches \n)
	assert "c\nt" in pats;
	assert "cat" in pats;

	# /foo.|bar/is - both flags (case insensitive + . matches \n)
	assert "FOO\n" in pats;
	assert "bar" in pats;
	assert "BAR" in pats;

	# /plain/ - no flags, case sensitive
	assert "plain" in pats;
	assert "PLAIN" !in pats;

	Input::remove("pats");
	terminate();
	}
