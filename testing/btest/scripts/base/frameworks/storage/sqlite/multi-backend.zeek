# @TEST-DOC: Opens multiple separate sqlite backends simultaneously to ensure data is written into the correct tables
#
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: sqlite3 test1.sqlite "select * from testing" > test1-testing.out
# @TEST-EXEC: sqlite3 test2.sqlite "select * from testing1" > test2-testing1.out
# @TEST-EXEC: sqlite3 test2.sqlite "select * from testing2" > test2-testing2.out
# @TEST-EXEC: btest-diff test1-testing.out
# @TEST-EXEC: btest-diff test2-testing1.out
# @TEST-EXEC: btest-diff test2-testing2.out

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

event zeek_init()
	{
	# Create a database file in the .tmp directory with a 'testing' table
	local opts1: Storage::BackendOptions = [$sqlite = [$database_path="test1.sqlite",
							   $table_name="testing"],
						$serializer=Storage::STORAGE_SERIALIZER_JSON];
	local opts2: Storage::BackendOptions = [$sqlite = [$database_path="test2.sqlite",
							   $table_name="testing1"],
						$serializer=Storage::STORAGE_SERIALIZER_JSON];
	local opts3: Storage::BackendOptions = [$sqlite = [$database_path="test2.sqlite",
							   $table_name="testing2"],
						$serializer=Storage::STORAGE_SERIALIZER_JSON];

	local res1 = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_SQLITE, opts1, string, string);
	local res2 = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_SQLITE, opts2, string, string);
	local res3 = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_SQLITE, opts3, string, string);

	Storage::Sync::put(res1$value, [$key="abc", $value="abc"]);
	Storage::Sync::put(res2$value, [$key="def", $value="def"]);
	Storage::Sync::put(res3$value, [$key="ghi", $value="ghi"]);

	Storage::Sync::close_backend(res1$value);
	Storage::Sync::close_backend(res2$value);
	Storage::Sync::close_backend(res3$value);
}
