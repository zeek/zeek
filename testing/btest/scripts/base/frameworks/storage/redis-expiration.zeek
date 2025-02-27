# @TEST-DOC: Tests expiration of data from Redis when reading a pcap

# @TEST-REQUIRES: have-redis
# @TEST-PORT: REDIS_PORT

# @TEST-EXEC: btest-bg-run redis-server run-redis-server ${REDIS_PORT%/tcp}
# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek -B storage -b -Cr - %INPUT > out
# @TEST-EXEC: btest-bg-wait -k 1

# @TEST-EXEC: btest-diff out

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/redis

redef Storage::expire_interval = 2secs;
redef exit_only_after_terminate = T;

# Create a typename here that can be passed down into open_backend()
type str: string;

global b: opaque of Storage::BackendHandle;
global key: string = "key1234";
global value: string = "value7890";

event check_removed()
	{
	local res2 = Storage::Sync::get(b, key);
	print "get result after expiration", res2;

	Storage::Sync::close_backend(b);
	terminate();
	}

event setup_test()
	{
	local opts: Storage::BackendOptions;
	opts$redis = [ $server_host="127.0.0.1", $server_port=to_port(getenv(
	    "REDIS_PORT")), $key_prefix="testing" ];

	local open_res = Storage::Sync::open_backend(Storage::REDIS, opts, str, str);
	print "open result", open_res;

	b = open_res$value;

	local res = Storage::Sync::put(b, [ $key=key, $value=value, $expire_time=2secs ]);
	print "put result", res;

	local res2 = Storage::Sync::get(b, key);
	print "get result", res2;
	if ( res2$code == Storage::SUCCESS && res2?$value )
		print "get result same as inserted", value == ( res2$value as string );

	schedule 5secs { check_removed() };
	}

event zeek_init()
	{
	# We need network time to be set to something other than zero for the
	# expiration time to be set correctly. Schedule an event on a short
	# timer so packets start getting read and do the setup there.
	schedule 100msecs { setup_test() };
	}
