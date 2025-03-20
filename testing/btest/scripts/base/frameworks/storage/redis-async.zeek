# @TEST-DOC: Tests basic Redis storage backend functions in async mode

# @TEST-REQUIRES: have-redis
# @TEST-PORT: REDIS_PORT

# @TEST-EXEC: btest-bg-run redis-server run-redis-server ${REDIS_PORT%/tcp}
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-bg-wait -k 0

# @TEST-EXEC: btest-diff out

@load base/frameworks/storage/async
@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/redis

redef exit_only_after_terminate = T;

event zeek_init()
	{
	local opts: Storage::BackendOptions;
	opts$redis = [ $server_host="127.0.0.1", $server_port=to_port(getenv(
	    "REDIS_PORT")), $key_prefix="testing" ];

	local key = "key1234";
	local value = "value5678";

	when [opts, key, value] ( local open_res = Storage::Async::open_backend(
	    Storage::REDIS, opts, string, string) )
		{
		print "open result", open_res;
		local b = open_res$value;

		when [b, key, value] ( local put_res = Storage::Async::put(b, [ $key=key,
		    $value=value ]) )
			{
			print "put result", put_res;

			when [b, key, value] ( local get_res = Storage::Async::get(b, key) )
				{
				print "get result", get_res;
				if ( get_res$code == Storage::SUCCESS && get_res?$value )
					print "get result same as inserted", value == ( get_res$value as string );

				when [b] ( local close_res = Storage::Async::close_backend(b) )
					{
					print "close result", close_res;
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
