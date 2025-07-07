# @TEST-DOC: Basic functionality for storage: opening/closing an sqlite backend, storing/retrieving data, using async methods
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

@load base/frameworks/storage/async
@load policy/frameworks/storage/backend/sqlite
@load base/frameworks/telemetry

# Make sure the telemetry output is in a fixed order.
redef running_under_test = T;

redef exit_only_after_terminate = T;

global b : opaque of Storage::BackendHandle;

event print_metrics_and_close()
	{
	print "";
	print "Post-operation metrics:";
	local storage_metrics = Telemetry::collect_metrics("zeek", "storage*");
	for (i in storage_metrics)
		{
		local m = storage_metrics[i];
		print m$opts$metric_type, m$opts$prefix, m$opts$name, m$label_names, m$label_values, m$value;
		}
	print "";

	when [] ( local close_res = Storage::Async::close_backend(b) )
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

event Storage::backend_opened(tag: Storage::Backend, config: any) {
	print "Storage::backend_opened", tag, config;
}

event zeek_init()
	{
	# Create a database file in the .tmp directory with a 'testing' table
	local opts: Storage::BackendOptions;
	opts$serializer = Storage::STORAGE_SERIALIZER_JSON;
	opts$sqlite = [ $database_path="test.sqlite", $table_name="testing" ];

	local key = "key1234";
	local value = "value5678";

	# Test inserting/retrieving a key/value pair that we know won't be in
	# the backend yet.
	when [opts, key, value] ( local open_res = Storage::Async::open_backend(
	    Storage::STORAGE_BACKEND_SQLITE, opts, string, string) )
		{
		print "open result", open_res;
		b = open_res$value;

		when [key, value] ( local put_res = Storage::Async::put(b, [ $key=key,
		    $value=value ]) )
			{
			print "put result", put_res;

			when [key, value] ( local get_res = Storage::Async::get(b, key) )
				{
				print "get result", get_res;
				if ( get_res$code == Storage::SUCCESS && get_res?$value )
					print "get result same as inserted", value == ( get_res$value as string );

				schedule 100 msec { print_metrics_and_close() };
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
