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
/baz/	baz-case-sensitive
/baz/i	baz-case-insensitive
/baz/s	baz-single-line
/baz/is	baz-both
/baz/si	baz-both-reversed
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
	# Only valid patterns should be loaded (8 of 11 entries). invalid-* are
	# ignored and logged. Order for /s and /i do not matter so baz-both and
	# baz-both-reversed are considered identical and the latter overwrites
	# the former.
	assert |pats| == 8;

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
