# @TEST-DOC: Query entry count from a Redis backend via size

# @TEST-REQUIRES: have-redis
# @TEST-PORT: REDIS_PORT

# @TEST-EXEC: btest-bg-run redis-server run-redis-server ${REDIS_PORT%/tcp}
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait -k 0

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/redis

event zeek_init()
	{
	local opts: Storage::BackendOptions;
	opts$redis = [ $server_host="127.0.0.1", $server_port=to_port(getenv("REDIS_PORT")),
	               $key_prefix="test-size" ];

	local open_res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_REDIS, opts, string, count);
	assert open_res$code == Storage::SUCCESS, fmt("open failed: %s", open_res$code);
	local b = open_res$value;

	# Empty backend.
	local res = Storage::Sync::size(b);
	assert res$code == Storage::SUCCESS, fmt("size failed: %s", res$code);
	assert res$value as count == 0, fmt("expected 0, got %d", res$value as count);

	# Insert entries.
	Storage::Sync::put(b, [ $key="a", $value=1 ]);
	Storage::Sync::put(b, [ $key="b", $value=2 ]);
	Storage::Sync::put(b, [ $key="c", $value=3 ]);

	res = Storage::Sync::size(b);
	assert res$code == Storage::SUCCESS;
	assert res$value as count == 3, fmt("expected 3, got %d", res$value as count);

	Storage::Sync::close_backend(b);
	}
