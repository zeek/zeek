# @TEST-EXEC: btest-bg-run master "zeek -b %INPUT >out"
# @TEST-EXEC: btest-bg-wait 60
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff master/out


event zeek_init()
	{
	local cv = Broker::vector_create();
	print Broker::vector_size(cv);
	print Broker::vector_insert(cv, 0, "hi");
	print Broker::vector_insert(cv, 1, "hello");
	print Broker::vector_insert(cv, 2, "greetings");
	print Broker::vector_insert(cv, 1, "salutations");
	print Broker::vector_size(cv);
	print cv, (cv as vector of string);
	local i = Broker::vector_iterator(cv);
	while ( ! Broker::vector_iterator_last(i) )
		{
		print fmt("| %s", Broker::vector_iterator_value(i));
		Broker::vector_iterator_next(i);
		}
	print "";
	
	print Broker::vector_replace(cv, 2, "bah");
	print cv, (cv as vector of string);
	print "";
	
	print Broker::vector_lookup(cv, 2);
	print Broker::vector_lookup(cv, 0);
	print cv, (cv as vector of string);
	print "";
	
	print Broker::vector_remove(cv, 2);
	print cv, (cv as vector of string);
	print "";
	
	print Broker::vector_size(cv);
	print Broker::vector_clear(cv);
	print Broker::vector_size(cv);
	print cv, (cv as vector of string);
	print "";
	}
