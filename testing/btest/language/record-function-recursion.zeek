# @TEST-EXEC: zeek -b %INPUT 2>&1 >out
# @TEST-EXEC: btest-diff out

type Outer: record {
	id: count &optional;
};

type Inner: record {
	create: function(input: Outer) : string;
};

redef record Outer += {
	inner: Inner &optional;
};

event zeek_init() {
	local o = Outer();
	print o;
	print type_name(o);
}
