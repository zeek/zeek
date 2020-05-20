# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type my_table: table[string] of double;

type my_record: record {
	i: int &default = 1;
	d: double &default = 3;
};

global t: my_table &default = 7;
global r = my_record();

function foo(i: int &default = 237, d: double &default = 101)
	{
	print i, d;
	}

event zeek_init()
	{
	print t["nope"];
	print r;
	foo();
	foo(-5);
	foo(-37, -8.1);
	}
