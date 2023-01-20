# @TEST-DOC: Populate a database, corrupt it then observe Zeek's behavior deleting the database and reopening it.
# @TEST-REQUIRES: dd --version > dd-version.txt
# @TEST-REQUIRES: test -e /dev/zero
# @TEST-EXEC: zeek -b %INPUT >> out

# Evil
# @TEST-EXEC: dd if=/dev/zero of=path_to_db.sqlite seek=512 count=32 bs=1
# @TEST-EXEC: zeek -b %INPUT >> out
#
# @TEST-EXEC: grep 'database disk image is malformed' .stderr
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
				$failure_mode=Broker::DELETE,
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
		test_table[cat(i)] = i;
	print fmt("populated %s rows", rows);
	}
