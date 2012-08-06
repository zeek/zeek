# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

event bro_init()
	{
	Intel::insert([$ip=1.2.3.4, $meta=[$source="source1-feed1", $class=Intel::MALICIOUS, $tags=set("foo")]]);
	Intel::insert([$ip=1.2.3.4, $meta=[$source="source2-special-sauce", $class=Intel::MALICIOUS, $tags=set("foo","bar")]]);

	# Lookup should return the items matching the query.
	local items = Intel::lookup([$ip=1.2.3.4]);
	print fmt("Number of matching intel items: %d (should be 2)", |items|);

	# This can be considered an update of a previous value since the
	# data, source, and class are the matching points for determining sameness.
	Intel::insert([$ip=1.2.3.4, $meta=[$source="source2-special-sauce", $class=Intel::MALICIOUS, $tags=set("foobar", "testing")]]);
	items = Intel::lookup([$ip=1.2.3.4]);
	print fmt("Number of matching intel items: %d (should still be 2)", |items|);

	# This is a new value.
	Intel::insert([$ip=1.2.3.4, $meta=[$source="source3", $class=Intel::MALICIOUS]]);
	items = Intel::lookup([$ip=1.2.3.4]);
	print fmt("Number of matching intel items: %d (should be 3)", |items|);
	}
