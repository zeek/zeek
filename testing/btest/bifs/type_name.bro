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
	local c = -3;
	local d = 3.14;
	local e = T;
	local f = current_time();
	local g = 5hr;
	local h = /^foo|bar/;
	local i = Blue;
	local j = 123/tcp;
	local k = 192.168.0.2;
	local l = [fe80::1];
	local m = 192.168.0.0/16;
	local n = [fe80:1234::]/32;
	local o = vector( 1, 2, 3);
	local p: vector of string = vector( "bro", "test" );
	local q = set( 1, 2, 3);
	local r = set( "this", "test");
	local s: table[count] of string = { [1] = "test", [2] = "bro" };
	local t: table[string] of count = { ["a"] = 5, ["b"] = 3 };
	local u: myrecord = [ $c = 2, $s = "another test" ];
	local v = function(aa: int, bb: int): bool { return aa < bb; };
	local w = function(): any { };
	local x = function() { };
	local y = open("deleteme");

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
	print type_name(u);
	print type_name(v);
	print type_name(w);
	print type_name(x);
	print type_name(y);
	print type_name(bro_init);
	}
