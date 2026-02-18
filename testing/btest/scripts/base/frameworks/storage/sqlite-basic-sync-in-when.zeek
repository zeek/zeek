# @TEST-DOC: Basic functionality for storage: opening/closing an sqlite backend, storing/retrieving data, using sync methods in when conditions
# TODO: This test hangs indefinitely on Windows and is skipped for the time being.
# @TEST-REQUIRES: ! is-windows
#
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

redef exit_only_after_terminate = T;

event Storage::backend_opened(tag: Storage::Backend, config: any) {
	print "Storage::backend_opened", tag, config;
}

event zeek_init()
	{
	# Create a database file in the .tmp directory with a 'testing' table
	local opts: Storage::BackendOptions;
	opts$sqlite = [ $database_path="test.sqlite", $table_name="testing" ];

	local key = "key1234";
	local value = "value5678";

	# Test inserting/retrieving a key/value pair that we know won't be in
	# the backend yet.
	when [opts, key, value] ( local open_res = Storage::Sync::open_backend(
	    Storage::STORAGE_BACKEND_SQLITE, opts, string, string) )
		{
		print "open result", open_res;
		local b = open_res$value;

		when [b, key, value] ( local put_res = Storage::Sync::put(b, [ $key=key,
		    $value=value ]) )
			{
			print "put result", put_res;

			when [b, key, value] ( local get_res = Storage::Sync::get(b, key) )
				{
				print "get result", get_res;
				if ( get_res$code == Storage::SUCCESS && get_res?$value )
					print "get result same as inserted", value == ( get_res$value as string );

				when [b] ( local close_res = Storage::Sync::close_backend(b) )
					{
					print "closed succesfully";
					terminate();
					}
				timeout 5sec
					{
					print "close request timed out";
					terminate();
					}
				}
			timeout 5sec
				{
				print "get request timed out";
				terminate();
				}
			}
		timeout 5sec
			{
			print "put request timed out";
			terminate();
			}
		}
	timeout 5sec
		{
		print "open request timed out";
		terminate();
		}
	}
