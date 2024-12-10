# @TEST-DOC: Tests various error handling scenarios for the storage framework
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

@load base/frameworks/storage
@load base/frameworks/reporter
@load policy/frameworks/storage/backend/sqlite

# Create a typename here that can be passed down into open_backend.
type str: string;

event zeek_init() {
	# Test opening a database with an invalid path
	local opts : Storage::Backend::SQLite::Options;
	opts$database_path = "/this/path/should/not/exist/test.sqlite";
	opts$table_name = "testing";

	# This should report an error in .stderr and reporter.log
	local b = Storage::open_backend(Storage::SQLITE, opts, str, str);

	# Open a valid database file
	opts$database_path = "test.sqlite";
	b = Storage::open_backend(Storage::SQLITE, opts, str, str);

	local bad_key: count = 12345;
	local value = "abcde";
	Storage::put(b, [$key=bad_key, $value=value, $async_mode=F]);

	# Close the backend and then attempt to use the closed handle
	Storage::close_backend(b);
	local res = Storage::put(b, [$key="a", $value="b", $async_mode=F]);
	print fmt("Put result on closed handle: %d", res);
}
