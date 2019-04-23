# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

# This test checks whether records with complex fields (tables, sets, vectors)
# can be used as table/set indices.

type MetaData: record {
	a: count;
	tags_v: vector of count;
	tags_t: table[string] of count;
	tags_s: set[string];
};

global ip_data: table[addr] of set[MetaData] = table();

global t1_t: table[string] of count = { ["one"] = 1, ["two"] = 2 };
global t2_t: table[string] of count = { ["four"] = 4, ["five"] = 5 };

global t1_v: vector of count = vector();
global t2_v: vector of count = vector();
t1_v[0] = 0;
t1_v[1] = 1;
t2_v[2] = 2;
t2_v[3] = 3;

local m: MetaData = [$a=4, $tags_v=t1_v, $tags_t=t1_t, $tags_s=set("a", "b")];
local n: MetaData = [$a=13, $tags_v=t2_v, $tags_t=t2_t, $tags_s=set("c", "d")];

if ( 1.2.3.4 !in ip_data )
	ip_data[1.2.3.4] = set(m);
else
	add ip_data[1.2.3.4][m];

print ip_data;

add ip_data[1.2.3.4][n];

print ip_data[1.2.3.4];
