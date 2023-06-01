#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

module Monochrome;
export {
	type color: enum { BLACK, WHITE };
}

module GLOBAL;

type color: enum { RED, BLUE };

type myrec: record {
	myfield: bool;
};

type tt: record {
	a: bool;
	b: string &default="Bar";
	c: double &optional;
	d: string &log;
	e: color &default=BLUE;
	f: Monochrome::color &log;
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
     c: set[double, tt];
     d: table[double, string] of table[string] of vector of string;
     e: vector of vector of string;
     f: vector of color;
     g: table[string] of color;
};

event zeek_init()
{
    local x: r = [$a=42, $d="Bar", $e=tt];
    print x;
    local t: record_field_table;
    t = record_fields(x);
    print t;
    print "c value", t["c"]?$value;
    print "c default ", t["c"]?$default_val;
    print "c optional", t["c"]$optional;

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
