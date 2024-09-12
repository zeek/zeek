# @TEST-DOC: Automatic expiration of stored data
# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

@load base/frameworks/storage

redef Storage::expire_interval = 5 secs;
redef exit_only_after_terminate = T;

# Create a typename here that can be passed down into get().
type str: string;

global backend: opaque of Storage::BackendHandle;
global key: string = "key1234";
global value: string = "value7890";

event check_removed() {
	local res2 = Storage::get(backend, key, F);
	print "get result", res2;

	Storage::close_backend(backend);
	terminate();
}

event zeek_init() {
	local opts : Storage::SqliteOptions;
	opts$database_path = "storage-test.sqlite";
	opts$table_name = "testing";

	backend = Storage::open_backend(Storage::SQLITE, opts, str, str);

	local res = Storage::put([$backend=backend, $key=key, $value=value, $overwrite=T,
	                          $expire_time=2 secs, $async_mode=F]);
	print "put result", res;

	local res2 = Storage::get(backend, key, F);
	print "get result", res2;
	print "get result same as inserted", value == (res2 as string);

	schedule 7 secs { check_removed() };
}
