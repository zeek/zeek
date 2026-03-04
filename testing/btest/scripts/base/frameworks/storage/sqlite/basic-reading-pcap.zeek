# @TEST-DOC: Tests that sqlite async works fine while reading pcaps
# TODO: This test hangs indefinitely on Windows and is skipped for the time being.
# @TEST-REQUIRES: ! is-windows
#
# @TEST-EXEC: zeek -r $TRACES/http/get.trace %INPUT > out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

@load base/frameworks/storage/async
@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

redef exit_only_after_terminate = T;

event zeek_init()
	{
	# Create a database file in the .tmp directory with a 'testing' table
	local opts: Storage::BackendOptions;
	opts$sqlite = [ $database_path="test.sqlite", $table_name="testing" ];

	local key = "key1234";
	local value = "value5678";

	# Test inserting/retrieving a key/value pair that we know won't be in
	# the backend yet.
	local open_res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_SQLITE, opts, string, string);
	print "open result", open_res;

	local b = open_res$value;

	when [b, key, value] ( local res = Storage::Async::put(b, [ $key=key,
	    $value=value ]) )
		{
		print "put result", res;

		when [b, key, value] ( local res2 = Storage::Async::get(b, key) )
			{
			print "get result", res2;
			if ( res2$code == Storage::SUCCESS && res2?$value )
				print "get result same as inserted", value == ( res2$value as string );

			Storage::Sync::close_backend(b);

			terminate();
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
