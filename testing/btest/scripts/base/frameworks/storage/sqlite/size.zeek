# @TEST-DOC: Query entry count from a SQLite backend via size
# @TEST-EXEC: zeek -b %INPUT

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

event zeek_init()
	{
	local opts: Storage::BackendOptions;
	opts$sqlite = [ $database_path="test.sqlite", $table_name="testing" ];

	local open_res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_SQLITE, opts, string, count);
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

	# Insert an already-expired entry.
	Storage::Sync::put(b, [ $key="expired", $value=4, $expire_time=-1sec ]);

	res = Storage::Sync::size(b);
	assert res$code == Storage::SUCCESS;
	assert res$value as count == 3, fmt("expected 3 (expired not counted), got %d", res$value as count);

	# Erase an entry.
	Storage::Sync::erase(b, "a");

	res = Storage::Sync::size(b);
	assert res$code == Storage::SUCCESS;
	assert res$value as count == 2, fmt("expected 2 after erase, got %d", res$value as count);

	Storage::Sync::close_backend(b);
	}
