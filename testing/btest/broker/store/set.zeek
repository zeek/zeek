# @TEST-EXEC: btest-bg-run master "zeek -b %INPUT >out"
# @TEST-EXEC: btest-bg-wait 60
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff master/out


event zeek_init()
	{
	local cs = Broker::set_create();
	
	print Broker::set_size(cs);
	print Broker::set_insert(cs, "hi");
	print Broker::set_size(cs);
	print Broker::set_contains(cs, "hi");
	print Broker::set_contains(cs, "bye");
	print Broker::set_insert(cs, "bye");

	print cs, (cs as set[string]);
	local i = Broker::set_iterator(cs);
 	while ( ! Broker::set_iterator_last(i) )
		{
		print fmt("| %s", Broker::set_iterator_value(i));
		Broker::set_iterator_next(i);
		}
	print "";
	
	print Broker::set_size(cs);
	print Broker::set_insert(cs, "bye");
	print Broker::set_size(cs);
	print Broker::set_remove(cs, "hi");
	print Broker::set_size(cs);
	print Broker::set_remove(cs, "hi");
	print cs, (cs as set[string]);
	print "";
	
	print Broker::set_clear(cs);
	print Broker::set_size(cs);
	print cs, (cs as set[string]);
	print "";
	}
