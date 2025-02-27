# @TEST-DOC: Tests basic Redis storage backend functions in sync mode, including overwriting

# @TEST-REQUIRES: have-redis
# @TEST-PORT: REDIS_PORT

# @TEST-EXEC: btest-bg-run redis-server run-redis-server ${REDIS_PORT%/tcp}
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-bg-wait -k 0

# @TEST-EXEC: btest-diff out

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/redis

# Create a typename here that can be passed down into open_backend()
type str: string;

event zeek_init()
	{
	local opts: Storage::BackendOptions;
	opts$redis = [ $server_host="127.0.0.1", $server_port=to_port(getenv(
	    "REDIS_PORT")), $key_prefix="testing" ];

	local key = "key1234";
	local value = "value1234";

	local open_res = Storage::Sync::open_backend(Storage::REDIS, opts, str, str);
	print "open_result", open_res;

	local b = open_res$value;

	local res = Storage::Sync::put(b, [ $key=key, $value=value ]);
	print "put result", res;

	local res2 = Storage::Sync::get(b, key);
	print "get result", res2;
	if ( res2$code == Storage::SUCCESS && res2?$value )
		print "get result same as inserted", value == ( res2$value as string );

	local value2 = "value5678";
	res = Storage::Sync::put(b, [ $key=key, $value=value2, $overwrite=T ]);
	print "overwrite put result", res;

	res2 = Storage::Sync::get(b, key);
	print "get result", res2;
	if ( res2$code == Storage::SUCCESS && res2?$value )
		print "get result same as inserted", value2 == ( res2$value as string );

	Storage::Sync::close_backend(b);
	}
