# @TEST-DOC: Tests basic Redis storage backend functions in async mode

# @TEST-REQUIRES: have-redis
# @TEST-PORT: REDIS_PORT

# @TEST-EXEC: btest-bg-run redis-server run-redis-server ${REDIS_PORT%/tcp}
# @TEST-EXEC: zeek -b %INPUT | sed "s|-${REDIS_PORT%/tcp}-|-XXXX-|g" > out
# @TEST-EXEC: btest-bg-wait -k 0

# @TEST-EXEC: btest-diff out

@load base/frameworks/storage/async
@load policy/frameworks/storage/backend/redis
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
	for (_, m in storage_metrics)
		{
		print m$opts$metric_type, m$opts$prefix, m$opts$name, m$label_names, m$label_values, m$value;
		}
	print "";

	when [] ( local close_res = Storage::Async::close_backend(b) )
		{
		print "close result", close_res;
		terminate();
		}
	timeout 5sec
		{
		print "close result", close_res;
		terminate();
		}
	}

event zeek_init()
	{
	local opts: Storage::BackendOptions;
	opts$redis = [ $server_host="127.0.0.1", $server_port=to_port(getenv(
	    "REDIS_PORT")), $key_prefix="testing" ];

	local key = "key1234";
	local value = "value5678";

	when [opts, key, value] ( local open_res = Storage::Async::open_backend(
	    Storage::STORAGE_BACKEND_REDIS, opts, string, string) )
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
