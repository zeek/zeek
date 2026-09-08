# @TEST-DOC: Retrieve all entries from a Redis backend via get_all

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
	               $key_prefix="test-get-all" ];

	local open_res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_REDIS, opts, string, count);
	assert open_res$code == Storage::SUCCESS, fmt("open failed: %s", open_res$code);
	local b = open_res$value;

	local input: table[string] of count = { ["a"] = 1, ["b"] = 2, ["c"] = 3 };
	for ( k, v in input )
		Storage::Sync::put(b, [ $key=k, $value=v ]);

	# Retrieve all entries.
	local res = Storage::Sync::get_all(b, 0);
	assert res$code == Storage::SUCCESS, fmt("get_all failed: %s", res$code);
	local t = res$value as table[string] of count;
	assert |t| == |input|, fmt("size mismatch: %d != %d", |t|, |input|);
	for ( k, v in input )
		assert k in t && t[k] == v, fmt("missing or wrong entry for key %s", k);

	# Test max_entries exceeded.
	local res2 = Storage::Sync::get_all(b, 2);
	assert res2$code == Storage::RESULT_TOO_LARGE, fmt("expected RESULT_TOO_LARGE, got %s", res2$code);

	# Test with exact limit.
	local res3 = Storage::Sync::get_all(b, 3);
	assert res3$code == Storage::SUCCESS, fmt("get_all with exact limit failed: %s", res3$code);

	Storage::Sync::close_backend(b);
	}
