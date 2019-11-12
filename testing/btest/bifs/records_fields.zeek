#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type myrec: record {
	myfield: bool;
};

type tt: record {
	a: bool;
	b: string &default="Bar";
	c: double &optional;
	d: string &log;
	m: myrec;
};

type r: record {
	a: count;
	b: string &default="Foo";
	c: double &optional;
	d: string &log;
	e: any;
};

type mystring: string;

type cr: record {
     a: set[double];
     b: set[double, string];
     c: table[double, string] of string;
     d: vector of string;
};

event zeek_init()
{
    local x: r = [$a=42, $d="Bar", $e=tt];
    print x;
    local t: record_field_table;
    t = record_fields(x);
    print t;
    print t["c"]?$value;

    t = record_fields(x$e);
    print t;
    t = record_fields(tt);
    print t;

    x = [$a=42, $d="Bar", $e=mystring];
    t = record_fields(x);
    print t;
    t = record_fields(x$e);
    print t;

    print record_fields("myrec");
    print record_fields("tt");
    print record_fields("r");

    print record_fields("cr");
}
