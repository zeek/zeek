#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
{
	local a = "this is a string";
	local b = "this is a tring";
	local c = "this is a strings";
	local d = "this is a strink";
	
	print levenshtein_distance(a, b);
	print levenshtein_distance(b, a);

	print levenshtein_distance(a, c);
	print levenshtein_distance(c, a);

	print levenshtein_distance(a, d);
	print levenshtein_distance(d, a);

	print levenshtein_distance(d, "");
	print levenshtein_distance("", d);
	print levenshtein_distance("", "");
	print levenshtein_distance(d, d);

	print levenshtein_distance("kitten", "sitting");
}
