# @TEST-DOC: Configure a broker store to be in WAL mode withou journal_mode NORMAL.
# @TEST-REQUIRES: sqlite3 --version
# @TEST-EXEC: zeek -b %INPUT > out 2>&1
#
# This is poking a bit at SQLite internals, but because WAL mode
# was flipped on, expect a wal and a shm file to exist.
# @TEST-EXEC: test -f path_to_db.sqlite || ls -lha >> out
# @TEST-EXEC: test -f path_to_db.sqlite-shm || ls -lha >> out
# @TEST-EXEC: test -f path_to_db.sqlite-wal || ls -lha >> out

# More poking, running sqlite3 should detect WAL mode, and the store
# table has 100 entries.
#
# @TEST-EXEC: sqlite3 ./path_to_db.sqlite 'PRAGMA journal_mode' >> out;
# @TEST-EXEC: sqlite3 ./path_to_db.sqlite 'select count(*) from store' >> out;
#
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
				$synchronous=Broker::SQLITE_SYNCHRONOUS_NORMAL,
				$journal_mode=Broker::SQLITE_JOURNAL_MODE_WAL,
			),
		),
	);

	local rows = 100;
	local i = 0;
	while ( ++i <= rows )
		test_table[cat(|test_table|)] = i;
	print fmt("populated %s rows", rows);
	}
