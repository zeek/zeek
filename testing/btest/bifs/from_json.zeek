# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

module A;

type Color: enum {
	Red = 10,
	White = 20,
	Blue = 30
};

type Foo: record {
	hello: string;
	t: bool;
	f: bool;
	n: count &optional;
	m: count &optional;  # not in input
	def: count &default = 123;
	i: int;
	pi: double;
	a: string_vec;
	c1: Color;
	p: port;
	ti: time;
	it: interval;
	ad: addr;
	s: subnet;
	re: pattern;
	su: subnet_set;
	se: set[addr, port];
};

event zeek_init()
	{
	local json = "{\"hello\":\"world\",\"t\":true,\"f\":false,\"se\":[[\"192.168.0.1\", \"80/tcp\"], [\"2001:db8::1\", \"8080/udp\"]],\"n\":null,\"i\":123,\"pi\":3.1416,\"a\":[\"1\",\"2\",\"3\",\"4\"],\"su\":[\"[aa:bb::0]/32\",\"192.168.0.0/16\"],\"c1\":\"A::Blue\",\"p\":\"1500/tcp\",\"it\":5000,\"ad\":\"127.0.0.1\",\"s\":\"[::1/128]\",\"re\":\"/a/\",\"ti\":1681652265.042767}";
	print from_json(json, Foo);
	}

@TEST-START-NEXT
# argument type mismatch
event zeek_init()
	{
	print from_json("[]", 10);
	}

@TEST-START-NEXT
# JSON parse error
event zeek_init()
	{
	print from_json("{\"hel", string_vec);
	}

@TEST-START-NEXT
type bool_t: bool;
type Foo: record {
	a: bool;
};

# type mismatch error
event zeek_init()
	{
	print from_json("[]", bool_t);
	print from_json("{\"a\": \"hello\"}", Foo);
	}

@TEST-START-NEXT
# type unsupport error
event zeek_init()
	{
	print from_json("[]", table_string_of_string);
	}

@TEST-START-NEXT
type port_t: port;
# wrong port format
event zeek_init()
	{
	print from_json("\"80\"", port_t);
	}

@TEST-START-NEXT
type set_t: set[int, bool];
# index type doesn't match
event zeek_init()
	{
	print from_json("[[1, false], [2]]", set_t);
	print from_json("[[1, false], [2, 1]]", set_t);
	}

@TEST-START-NEXT
type pattern_t: pattern;
# pattern compile error
event zeek_init()
	{
	print from_json("\"/([[:print:]]{-}[[:alnum:]]foo)/\"", pattern_t);
	}

@TEST-START-NEXT
type Color: enum {
	Red = 10
};
# enum error
event zeek_init()
	{
	print from_json("\"Yellow\"", Color);
	}

@TEST-START-NEXT
# container null
event zeek_init()
	{
	print from_json("[\"fe80::/64\",null,\"192.168.0.0/16\"]", subnet_set);
	print from_json("[\"1\",null,\"3\",\"4\"]", string_vec);
	}

@TEST-START-NEXT
type Foo: record {
	hello: string;
	t: bool;
};
# record field null or missing
event zeek_init()
	{
	print from_json("{\"t\":null}", Foo);
	print from_json("{\"hello\": null, \"t\": true}", Foo);
	}

@TEST-START-NEXT
type Foo: record {
	hello: string;
};
# extra fields are alright
event zeek_init()
	{
	print from_json("{\"hello\": \"Hello!\", \"t\": true}", Foo);
	}
