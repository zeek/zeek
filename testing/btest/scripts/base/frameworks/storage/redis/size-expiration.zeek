# @TEST-DOC: size on Redis does not count entries whose TTL has fired

# @TEST-REQUIRES: have-redis
# @TEST-PORT: REDIS_PORT

# @TEST-EXEC: btest-bg-run redis-server run-redis-server ${REDIS_PORT%/tcp}
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait -k 0

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/redis

redef exit_only_after_terminate = T;

global b: opaque of Storage::BackendHandle;

event check_size()
	{
	local res = Storage::Sync::size(b);
	assert res$code == Storage::SUCCESS, fmt("size failed: %s", res$code);
	assert res$value as count == 1, fmt("expected 1 after expiry, got %d", res$value as count);

	Storage::Sync::close_backend(b);
	terminate();
	}

event setup_test()
	{
	local opts: Storage::BackendOptions;
	opts$redis = [ $server_host="127.0.0.1", $server_port=to_port(getenv("REDIS_PORT")),
	               $key_prefix="test-size-expire" ];

	local open_res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_REDIS, opts, string, count);
	assert open_res$code == Storage::SUCCESS, fmt("open failed: %s", open_res$code);
	b = open_res$value;

	Storage::Sync::put(b, [ $key="live", $value=1 ]);
	Storage::Sync::put(b, [ $key="expired", $value=2, $expire_time=1sec ]);

	# Wait for the TTL to fire.
	schedule 3secs { check_size() };
	}

event zeek_init()
	{
	schedule 100msecs { setup_test() };
	}
