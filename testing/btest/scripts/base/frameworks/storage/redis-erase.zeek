# @TEST-DOC: Tests basic Redis storage backend functions in sync mode, including overwriting

# @TEST-REQUIRES: have-redis
# @TEST-PORT: REDIS_PORT

# @TEST-EXEC: btest-bg-run redis-server run-redis-server ${REDIS_PORT%/tcp}
# @TEST-EXEC: zeek -b %INPUT | sed 's|=[0-9]*/tcp|=xxxx/tcp|g' > out
# @TEST-EXEC: btest-bg-wait -k 0

# @TEST-EXEC: btest-diff out

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/redis

event zeek_init()
	{
	local opts: Storage::BackendOptions;
	opts$redis = [ $server_host="127.0.0.1", $server_port=to_port(getenv(
	    "REDIS_PORT")), $key_prefix="testing" ];

	local key = "key1234";
	local value = "value1234";

	local open_res = Storage::Sync::open_backend(Storage::REDIS, opts, string, string);
	print "open_result", open_res;

	local b = open_res$value;

	local res = Storage::Sync::put(b, [ $key=key, $value=value ]);
	print "put result", res;

	res = Storage::Sync::get(b, key);
	print "get result", res;
	if ( res$code == Storage::SUCCESS && res?$value )
		print "get result same as inserted", value == ( res$value as string );

	res = Storage::Sync::erase(b, key);
	print "erase result", res;

	res = Storage::Sync::get(b, key);
	if ( res$code != Storage::SUCCESS )
		print "get result 2", res;

	Storage::Sync::close_backend(b);
	}
