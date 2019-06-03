# @TEST-EXEC: btest-bg-run master "zeek -b %INPUT >out"
# @TEST-EXEC: btest-bg-wait 60
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff master/out

type R: record  {
    s1: string;
    s2: string;
    c: count;
};

event zeek_init()
	{
	local cr = Broker::record_create(3);
	print Broker::record_size(cr);
	print Broker::record_assign(cr, 0, "hi");
	print Broker::record_assign(cr, 1, "hello");
	print Broker::record_assign(cr, 2, 37);
	print cr, (cr as R);
	print "";
	
	print Broker::record_lookup(cr, 0);
	print Broker::record_lookup(cr, 1);
	print Broker::record_lookup(cr, 2);
	print Broker::record_size(cr);
	print Broker::record_assign(cr, 1, "goodbye");
	print Broker::record_size(cr);
	print Broker::record_lookup(cr, 1);
	print cr, (cr as R);
	print "";

	local i = Broker::record_iterator(cr);
	while ( ! Broker::record_iterator_last(i) )
		{
		print fmt("| %s", Broker::record_iterator_value(i));
		Broker::record_iterator_next(i);
		}
	print "";
	}
