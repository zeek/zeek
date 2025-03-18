# @TEST-DOC: Tests that Redis storage backend defaults back to sync mode reading pcaps

# @TEST-REQUIRES: have-redis
# @TEST-PORT: REDIS_PORT

# @TEST-EXEC: btest-bg-run redis-server run-redis-server ${REDIS_PORT%/tcp}
# @TEST-EXEC: zeek -r $TRACES/http/get.trace -b %INPUT > out
# @TEST-EXEC: btest-bg-wait -k 0

# @TEST-EXEC: btest-diff out

@load base/frameworks/storage/sync
@load base/frameworks/storage/async
@load policy/frameworks/storage/backend/redis

# Create a typename here that can be passed down into open_backend()
type str: string;

event zeek_init()
	{
	local opts: Storage::BackendOptions;
	opts$redis = [ $server_host="127.0.0.1", $server_port=to_port(getenv(
	    "REDIS_PORT")), $key_prefix="testing" ];

	local key = "key1234";
	local value = "value5678";

	local open_res = Storage::Sync::open_backend(Storage::REDIS, opts, str, str);
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
			}
		timeout 5sec
			{
			print "get request timed out";
			}
		}
	timeout 5sec
		{
		print "put request timed out";
		}
	}
