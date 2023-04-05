# @TEST-EXEC: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out

module X;

export {
	global c: count = 1 &deprecated="removal planned";
}
event zeek_init()
	{
	print c;
@pragma push ignore-deprecations
	print c;
@pragma pop ignore-deprecations
	}

# @TEST-START-NEXT
type R: record {
	s: string &optional &deprecated="Use t instead of s";
	t: string;
};

type O: record {
	o: string;
};

event zeek_init()
	{
	local r1 = R($s="s1", $t="t1");
	print "s", r1$s;
	print "t", r1$t;
@pragma push ignore-deprecations
	local r2 = R($s="s2", $t="t2");
	print "s", r2$s;
	print "t", r2$t;
@pragma pop ignore-deprecations

	local o1 = O($o=r1$s);
	# Avoid warning when constructing O. This
	# looks fairly ugly, but hey, you should
	# not be doing this.
	local o2 = O(
@pragma push ignore-deprecations
		$o=r1$s,
@pragma pop
	);
	print "o1", o1;
	print "o2", o2;
	}


# @TEST-START-NEXT
@load ./deprecated
print "Deprecated::x", Deprecated::x;

# @TEST-START-NEXT
@pragma push ignore-deprecations
@load ./deprecated
@pragma pop

print "Deprecated::x", Deprecated::x;

# @TEST-START-FILE ./deprecated.zeek
@deprecated This script is deprecated.

module Deprecated;
export {
	option x: count = 42;
}

# @TEST-END-FILE
