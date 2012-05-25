#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

type color: enum { Red, Blue };

type myrecord: record {
  c: count;
  s: string;
};

event bro_init()
	{
	local a = "foo";
	local b = 3;
	local c = 3.14;
	local d = T;
	local e = current_time();
	local f = 5hr;
	local g = /^foo|bar/;
	local h = Blue;
	local i = 123/tcp;
	local j = 192.168.0.2;
	local k = [fe80::1];
	local l = 192.168.0.0/16;
	local m = [fe80:1234::]/32;
	local n = vector( 1, 2, 3);
	local o = vector( "bro", "test");
	local p = set( 1, 2, 3);
	local q = set( "this", "test");
	local r: table[count] of string = { [1] = "test", [2] = "bro" };
	local s: table[string] of count = { ["a"] = 5, ["b"] = 3 };
	local t: myrecord = [ $c = 2, $s = "another test" ];

	print type_name(a);
	print type_name(b);
	print type_name(c);
	print type_name(d);
	print type_name(e);
	print type_name(f);
	print type_name(g);
	print type_name(h);
	print type_name(i);
	print type_name(j);
	print type_name(k);
	print type_name(l);
	print type_name(m);
	print type_name(n);
	print type_name(o);
	print type_name(p);
	print type_name(q);
	print type_name(r);
	print type_name(s);
	print type_name(t);

	}
