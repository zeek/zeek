# @TEST-DOC: Tests expiration of data from Redis when reading a pcap

# @TEST-REQUIRES: have-redis
# @TEST-PORT: REDIS_PORT

# Generate a redis.conf file with the port defined above, but without the /tcp at the end of
# it. This also sets some paths in the conf to the testing directory.
# @TEST-EXEC: cat $FILES/redis.conf | sed "s|%REDIS_PORT%|${REDIS_PORT%/tcp}|g" | sed "s|%RUN_PATH%|$(pwd)|g" > ./redis.conf
# @TEST-EXEC: btest-bg-run redis redis-server ../redis.conf
# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek -B storage -b -Cr - %INPUT > out
# @TEST-EXEC: btest-bg-wait -k 1

# @TEST-EXEC: btest-diff out

@load base/frameworks/storage
@load policy/frameworks/storage/backend/redis

redef Storage::expire_interval = 2 secs;
redef exit_only_after_terminate = T;

# Create a typename here that can be passed down into open_backend()
type str: string;

global b: opaque of Storage::BackendHandle;
global key: string = "key1234";
global value: string = "value7890";

event check_removed() {
	local res2 = Storage::get(b, key, F);
	print "get result after expiration", res2;

	Storage::close_backend(b);
	terminate();
}

event setup_test() {
	local opts : Storage::Backend::Redis::Options;
	opts$server_host = "127.0.0.1";
	opts$server_port = to_port(getenv("REDIS_PORT"));
	opts$key_prefix = "testing";
	opts$async_mode = F;

	b = Storage::open_backend(Storage::REDIS, opts, str, str);

	local res = Storage::put(b, [$key=key, $value=value, $async_mode=F, $expire_time=2 secs]);
	print "put result", res;

	local res2 = Storage::get(b, key, F);
	print "get result", res2;
	print "get result same as inserted", value == (res2 as string);

	schedule 5 secs { check_removed() };
}

event zeek_init() {
	# We need network time to be set to something other than zero for the
	# expiration time to be set correctly. Schedule an event on a short
	# timer so packets start getting read and do the setup there.
	schedule 100 msecs { setup_test() };
}
