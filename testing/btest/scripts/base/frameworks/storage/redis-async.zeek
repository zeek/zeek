# @TEST-DOC: Tests basic Redis storage backend functions in async mode

# @TEST-REQUIRES: have-redis
# @TEST-PORT: REDIS_PORT

# Generate a redis.conf file with the port defined above, but without the /tcp at the end of
# it. This also sets some paths in the conf to the testing directory.
# @TEST-EXEC: cat $FILES/redis.conf | sed "s|%REDIS_PORT%|${REDIS_PORT%/tcp}|g" | sed "s|%RUN_PATH%|$(pwd)|g" > ./redis.conf
# @TEST-EXEC: btest-bg-run redis redis-server ../redis.conf
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-bg-wait -k 0

# @TEST-EXEC: btest-diff out

@load base/frameworks/storage/async
@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/redis

redef exit_only_after_terminate = T;

# Create a typename here that can be passed down into open_backend()
type str: string;

event zeek_init()
	{
	local opts: Storage::BackendOptions;
	opts$redis = [ $server_host="127.0.0.1", $server_port=to_port(getenv(
	    "REDIS_PORT")), $key_prefix="testing" ];

	local key = "key1234";
	local value = "value5678";

	when [opts, key, value] ( local open_res = Storage::Async::open_backend(
	    Storage::REDIS, opts, str, str) )
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
