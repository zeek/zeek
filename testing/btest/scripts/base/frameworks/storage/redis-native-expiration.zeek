# @TEST-DOC: Tests expiration of data from Redis when reading a pcap

# @TEST-REQUIRES: have-redis
# @TEST-PORT: REDIS_PORT

# @TEST-EXEC: btest-bg-run redis-server run-redis-server ${REDIS_PORT%/tcp}
# @TEST-EXEC: zeek -B storage -b %INPUT > out
# @TEST-EXEC: btest-bg-wait -k 1

# @TEST-EXEC: btest-diff out

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/redis

redef Storage::expire_interval = 2secs;
redef exit_only_after_terminate = T;

global b: opaque of Storage::BackendHandle;
global key1: string = "key1234";
global value1: string = "value1234";

global key2: string = "key2345";
global value2: string = "value2345";

event check_removed()
	{
	local res = Storage::Sync::get(b, key1);
	print "get result 1 after expiration", res;

	res = Storage::Sync::get(b, key2);
	print "get result 2 after expiration", res;

	Storage::Sync::close_backend(b);
	terminate();
	}

event setup_test()
	{
	local opts: Storage::BackendOptions;
	opts$redis = [ $server_host="127.0.0.1", $server_port=to_port(getenv(
	    "REDIS_PORT")), $key_prefix="testing" ];

	local open_res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_REDIS, opts, string, string);
	print "open result", open_res;

	b = open_res$value;

	# Insert a key that will expire in the time allotted
	local res = Storage::Sync::put(b, [ $key=key1, $value=value1, $expire_time=2secs ]);
	print "put result 1", res;

	# Insert a key that won't expire
	res = Storage::Sync::put(b, [ $key=key2, $value=value2, $expire_time=20secs ]);
	print "put result 2", res;

	res = Storage::Sync::get(b, key1);
	print "get result", res;
	if ( res$code == Storage::SUCCESS && res?$value )
		print "get result same as inserted", value1 == ( res$value as string );

	res = Storage::Sync::get(b, key2);
	print "get result 2", res;
	if ( res$code == Storage::SUCCESS && res?$value )
		print "get result 2 same as inserted", value2 == ( res$value as string );

	schedule 5secs { check_removed() };
	}

event zeek_init()
	{
	# We need network time to be set to something other than zero for the
	# expiration time to be set correctly. Schedule an event on a short
	# timer so packets start getting read and do the setup there.
	schedule 100msecs { setup_test() };
	}
