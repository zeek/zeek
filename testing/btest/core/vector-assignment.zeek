# @TEST-EXEC: zeek %INPUT

# This regression test checks a special case in the vector code. In this case
# UnaryExpr will be called with a Type() of any. Tests succeeds if it does not
# crash Bro.

type OptionCacheValue: record {
	val: any;
};

function set_me(val: any) {
	local a = OptionCacheValue($val=val);
	print a;
}

event zeek_init() {
	local b: vector of count = {1, 2, 3};
	set_me(b);
}
