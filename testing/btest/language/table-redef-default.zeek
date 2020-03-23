# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

const mymap: table[count] of string = {
	[1] = "one",
	[2] = "two",
} &default="original default" &redef;

redef mymap = {
	[1] = "uno",
} &default="some number";

print mymap[1];
print mymap[2];
