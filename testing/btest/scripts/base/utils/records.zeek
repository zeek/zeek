# @TEST-EXEC: zeek -b %INPUT > output
# @TEST-EXEC: btest-diff output

@load base/utils/records

event bro_init()
{
	local v: vector of string = vector();

	v += "a";
	v += "b";
	v += "c";
	v += "d";
	v += "e";

	print "============ vector remove 1 from head";
	print vector_remove_from_head(v, 1);

	print "============ vector remove 1 from tail";
	print vector_remove_from_tail(v, 1);
}
