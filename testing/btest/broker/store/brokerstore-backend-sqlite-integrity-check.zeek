# @TEST-DOC: Use SQLite backend option integrity_check, but not breaking anything.

# @TEST-EXEC: zeek -b %INPUT >> out
# @TEST-EXEC: zeek -b %INPUT >> out

# @TEST-EXEC: btest-diff out

@load base/frameworks/broker/store

global test_store: opaque of Broker::Store;
global test_table: table[string] of count &broker_store="test_store_42";

event zeek_init()
	{
	test_store = Broker::create_master(
		"test_store_42",
		Broker::SQLITE,
		Broker::BackendOptions(
			$sqlite=Broker::SQLiteOptions(
				$path="path_to_db.sqlite",
				$integrity_check=T,
			),
		),
	);
	if ( Broker::is_closed(test_store) ) {
		print("failed to open store");
		exit(1);
	} else {
		print("store is open");
	}

	local rows = 100;
	local i = 0;
	while ( ++i <= rows )
		test_table[cat(|test_table|)] = i;
	print fmt("populated %s rows", rows);
	}
