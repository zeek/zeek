#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

type r: record {
	a: count;
	b: string &default="Foo";
	c: double &optional;
	d: string &log;
};

event bro_init()
{
    local x: r = [$a=42, $d="Bar"];
    print x;
    local t: record_field_table;
    t = record_fields(x);
    print t;
    print t["c"]?$value;
}
