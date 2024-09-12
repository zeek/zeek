# @TEST-DOC: Basic functionality for storage: opening/closing an sqlite backend, storing/retrieving data, using async methods
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

@load base/frameworks/storage

redef exit_only_after_terminate = T;

# Create a typename here that can be passed down into get().
type str: string;

event zeek_init() {
	# Create a database file in the .tmp directory with a 'testing' table
	local opts : Storage::SqliteOptions;
	opts$database_path = "test.sqlite";
	opts$table_name = "testing";

	local key = "key1234";
	local value = "value5678";

	# Test inserting/retrieving a key/value pair that we know won't be in
	# the backend yet.
	local b = Storage::open_backend(Storage::SQLITE, opts, str, str);

	when [b, key, value] ( local res = Storage::put([$backend=b, $key=key, $value=value]) ) {
		print "put result", res;

		when [b, key, value] ( local res2 = Storage::get(b, key) ) {
			print "get result", res2;
			print "get result same as inserted", value == (res2 as string);

			Storage::close_backend(b);

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
