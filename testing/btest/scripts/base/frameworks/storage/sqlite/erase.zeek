# @TEST-DOC: Erase existing data in a SQLite backend
# @TEST-EXEC: cp $FILES/storage-test.sqlite ./storage-test.sqlite
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

event Storage::backend_opened(tag: Storage::Backend, config: any)
	{
	print "Storage::backend_opened", tag, config;
	}

event zeek_init()
	{
	# Create a database file in the .tmp directory with a 'testing' table
	local opts: Storage::BackendOptions;
	opts$sqlite = [ $database_path="storage-test.sqlite", $table_name="testing" ];

	local key = "key1234";

	# Test inserting/retrieving a key/value pair that we know won't be in
	# the backend yet.
	local open_res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_SQLITE, opts, string, string);
	print "open result", open_res;
	local b = open_res$value;

	local res = Storage::Sync::erase(b, key);
	print "erase result", res;

	local res2 = Storage::Sync::get(b, key);
	if ( res2$code != Storage::SUCCESS )
		print "get result", res2;

	Storage::Sync::close_backend(b);
	}
