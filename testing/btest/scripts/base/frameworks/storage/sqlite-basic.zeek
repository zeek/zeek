# @TEST-DOC: Basic functionality for storage: opening/closing an sqlite backend, storing/retrieving data, using async methods
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

@load base/frameworks/storage/async
@load policy/frameworks/storage/backend/sqlite

redef exit_only_after_terminate = T;

# Create a typename here that can be passed down into get().
type str: string;

event zeek_init() {
	# Create a database file in the .tmp directory with a 'testing' table
	local opts : Storage::BackendOptions;
	opts$sqlite = [$database_path = "test.sqlite", $table_name="testing"];

	local key = "key1234";
	local value = "value5678";

	# Test inserting/retrieving a key/value pair that we know won't be in
	# the backend yet.
	when [opts, key, value] ( local b = Storage::Async::open_backend(Storage::SQLITE, opts, str, str) ) {
		print "open successful";

		when [b, key, value] ( local put_res = Storage::Async::put(b, [$key=key, $value=value]) ) {
			print "put result", put_res;

			when [b, key, value] ( local get_res = Storage::Async::get(b, key) ) {
				print "get result", get_res;
				if ( get_res?$val )
					print "get result same as inserted", value == (get_res$val as string);

				when [b] ( local close_res = Storage::Async::close_backend(b) ) {
					print "closed succesfully";
					terminate();
				} timeout 5 sec {
					print "close request timed out";
					terminate();
				}
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
	timeout 5 sec {
		print "open request timed out";
		terminate();
	}
}
