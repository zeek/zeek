# @TEST-EXEC: btest-bg-run master "zeek -b %INPUT >out"
# @TEST-EXEC: btest-bg-wait 60
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff master/out


event zeek_init()
	{
	local ct = Broker::table_create();

	print Broker::table_size(ct);
	print Broker::table_insert(ct, "hi", 42);
	print Broker::table_size(ct);
	print Broker::table_contains(ct, "hi");
	print (Broker::table_lookup(ct, "hi") as count);
	print Broker::table_contains(ct, "bye");
	print Broker::table_insert(ct, "bye", 7);
	print Broker::table_size(ct);

	print ct, (ct as table[string] of count);
	local i = Broker::table_iterator(ct);
 	while ( ! Broker::table_iterator_last(i) )
		{
		print fmt("| %s", Broker::table_iterator_value(i));
		Broker::table_iterator_next(i);
		}
	print "";

	print Broker::table_insert(ct, "bye", 37);
	print ct, (ct as table[string] of count);
	print "";
	
	print Broker::table_size(ct);
	print (Broker::table_lookup(ct, "bye") as count);
	print Broker::table_remove(ct, "hi");
	print Broker::table_size(ct);
	print Broker::table_remove(ct, "hi");
	print Broker::table_size(ct);
	print Broker::table_clear(ct);
	print Broker::table_size(ct);
	print ct, (ct as table[string] of count);
	print "";
	}
