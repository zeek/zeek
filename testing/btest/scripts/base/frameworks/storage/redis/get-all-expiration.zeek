# @TEST-DOC: get_all on Redis does not return entries whose TTL has fired

# @TEST-REQUIRES: have-redis
# @TEST-PORT: REDIS_PORT

# @TEST-EXEC: btest-bg-run redis-server run-redis-server ${REDIS_PORT%/tcp}
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait -k 0

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/redis

redef exit_only_after_terminate = T;

global b: opaque of Storage::BackendHandle;

event check_get_all()
	{
	local res = Storage::Sync::get_all(b, 0);
	assert res$code == Storage::SUCCESS, fmt("get_all failed: %s", res$code);
	local t = res$value as table[string] of count;
	assert |t| == 1, fmt("expected 1 entry, got %d", |t|);
	assert "live" in t && t["live"] == 1;

	Storage::Sync::close_backend(b);
	terminate();
	}

event setup_test()
	{
	local opts: Storage::BackendOptions;
	opts$redis = [ $server_host="127.0.0.1", $server_port=to_port(getenv("REDIS_PORT")),
	               $key_prefix="test-get-all-expire" ];

	local open_res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_REDIS, opts, string, count);
	assert open_res$code == Storage::SUCCESS, fmt("open failed: %s", open_res$code);
	b = open_res$value;

	Storage::Sync::put(b, [ $key="live", $value=1 ]);
	Storage::Sync::put(b, [ $key="expired", $value=2, $expire_time=1sec ]);

	# Wait for the TTL to fire.
	schedule 3secs { check_get_all() };
	}

event zeek_init()
	{
	schedule 100msecs { setup_test() };
	}
