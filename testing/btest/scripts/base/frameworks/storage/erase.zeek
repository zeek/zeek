# @TEST-DOC: Erase existing data in a SQLite backend
# @TEST-EXEC: cp $FILES/storage-test.sqlite ./storage-test.sqlite
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

@load base/frameworks/storage
@load policy/frameworks/storage/backend/sqlite

# Create a typename here that can be passed down into get().
type str: string;

event zeek_init() {
	# Create a database file in the .tmp directory with a 'testing' table
	local opts : Storage::Backend::SQLite::Options;
	opts$database_path = "storage-test.sqlite";
	opts$table_name = "testing";

	local key = "key1234";

	# Test inserting/retrieving a key/value pair that we know won't be in
	# the backend yet.
	local b = Storage::open_backend(Storage::SQLITE, opts, str, str);

	local res = Storage::erase(b, key, F);
	print "erase result", res;

	local res2 = Storage::get(b, key, F);
	if ( res2?$error )
		print "get result", res2$error;

	Storage::close_backend(b);
}
