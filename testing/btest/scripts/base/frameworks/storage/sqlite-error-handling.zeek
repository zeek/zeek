# @TEST-DOC: Tests various error handling scenarios for the storage framework
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

@load base/frameworks/storage/sync
@load base/frameworks/reporter
@load policy/frameworks/storage/backend/sqlite

event zeek_init() {
	# Test opening a database with an invalid path
	local opts : Storage::BackendOptions;
	opts$sqlite = [$database_path = "/this/path/should/not/exist/test.sqlite",
	               $table_name = "testing"];

	# This should report an error in .stderr and reporter.log
	local open_res = Storage::Sync::open_backend(Storage::SQLITE, opts, string, string);
	print "Open result", open_res;

	# Open a valid database file
	opts$sqlite$database_path = "test.sqlite";
	open_res = Storage::Sync::open_backend(Storage::SQLITE, opts, string, string);
	print "Open result 2", open_res;

	local b = open_res$value;

	local bad_key: count = 12345;
	local value = "abcde";
	local res = Storage::Sync::put(b, [$key=bad_key, $value=value]);
	print "Put result with bad key type", res;

	# Close the backend and then attempt to use the closed handle
	Storage::Sync::close_backend(b);
	local res2 = Storage::Sync::put(b, [$key="a", $value="b"]);
	print "Put result on closed handle", res2;
}
