# @TEST-DOC: Automatic expiration of stored data
# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek -b -Cr - %INPUT > out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

redef Storage::expire_interval = 2 secs;
redef exit_only_after_terminate = T;

# Create a typename here that can be passed down into get().
type str: string;

global backend: opaque of Storage::BackendHandle;
global key: string = "key1234";
global value: string = "value7890";

event check_removed() {
	# This should return an error from the sqlite backend that there aren't any more
	# rows available.
	local res2 = Storage::Sync::get(backend, key);
	if ( res2$code != Storage::SUCCESS )
		print "get result", res2;

	Storage::Sync::close_backend(backend);
	terminate();
}

event setup_test() {
	local opts : Storage::BackendOptions;
	opts$sqlite = [$database_path = "storage-test.sqlite", $table_name = "testing"];

	local open_res = Storage::Sync::open_backend(Storage::SQLITE, opts, str, str);
	print "open result", open_res;
	backend = open_res$value;

	local res = Storage::Sync::put(backend, [$key=key, $value=value, $expire_time=2 secs]);
	print "put result", res;

	local res2 = Storage::Sync::get(backend, key);
	print "get result", res2;
	if ( res2$code == Storage::SUCCESS && res2?$value )
		print "get result same as inserted", value == (res2$value as string);

	schedule 5 secs { check_removed() };
}

event zeek_init() {
	# We need network time to be set to something other than zero for the
	# expiration time to be set correctly. Schedule an event on a short
	# timer so packets start getting read and do the setup there.
	schedule 100 msecs { setup_test() };
}
