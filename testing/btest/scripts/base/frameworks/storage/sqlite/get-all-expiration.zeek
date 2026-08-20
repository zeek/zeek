# @TEST-DOC: get_all filters out expired entries
# @TEST-EXEC: zeek -b %INPUT

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

event zeek_init()
	{
	local opts: Storage::BackendOptions;
	opts$sqlite = [ $database_path="test.sqlite", $table_name="testing" ];

	local open_res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_SQLITE, opts, string, count);
	local b = open_res$value;

	# Insert entries: one with no expiration, one already expired.
	Storage::Sync::put(b, [ $key="live", $value=1 ]);
	Storage::Sync::put(b, [ $key="expired", $value=2, $expire_time=-1sec ]);

	local res = Storage::Sync::get_all(b, 0);
	assert res$code == Storage::SUCCESS, fmt("get_all failed: %s", res$code);
	local t = res$value as table[string] of count;
	assert |t| == 1, fmt("expected 1 entry, got %d", |t|);
	assert "live" in t && t["live"] == 1;
	assert "expired" !in t, "expired entry should not be present";

	Storage::Sync::close_backend(b);
	}
