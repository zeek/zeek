# @TEST-DOC: Tests that sqlite async works fine while reading pcaps
# @TEST-EXEC: zeek -C -r $TRACES/http/get.trace %INPUT > out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

@load base/frameworks/storage/async
@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

redef exit_only_after_terminate = T;

# Create a typename here that can be passed down into get().
type str: string;

event zeek_init() {
	# Create a database file in the .tmp directory with a 'testing' table
	local opts : Storage::Backend::SQLite::Options;
	opts$database_path = "test.sqlite";
	opts$table_name = "testing";

	local key = "key1234";
	local value = "value5678";

	# Test inserting/retrieving a key/value pair that we know won't be in
	# the backend yet.
	local b = Storage::Sync::open_backend(Storage::SQLITE, opts, str, str);

	when [b, key, value] ( local res = Storage::Async::put(b, [$key=key, $value=value]) ) {
		print "put result", res;

		when [b, key, value] ( local res2 = Storage::Async::get(b, key) ) {
			print "get result", res2;
			if ( res2?$val )
				print "get result same as inserted", value == (res2$val as string);

			Storage::Sync::close_backend(b);

			terminate();
		}
		timeout 5 sec {
			print "get requeest timed out";
			terminate();
		}
	}
	timeout 5 sec {
		print "put request timed out";
		terminate();
	}
}
