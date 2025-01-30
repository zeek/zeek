# @TEST-DOC: Automatic expiration of stored data
# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek -b -Cr - %INPUT > out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

@load base/frameworks/storage
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
	local res2 = Storage::get(backend, key, F);
	if ( res2?$error )
		print "get result", res2$error;

	Storage::close_backend(backend);
	terminate();
}

event setup_test() {
	local opts : Storage::Backend::SQLite::Options;
	opts$database_path = "storage-test.sqlite";
	opts$table_name = "testing";

	backend = Storage::open_backend(Storage::SQLITE, opts, str, str);

	local res = Storage::put(backend, [$key=key, $value=value, $expire_time=2 secs, $async_mode=F]);
	print "put result", res;

	local res2 = Storage::get(backend, key, F);
	print "get result", res2;
	if ( res2?$val )
		print "get result same as inserted", value == (res2$val as string);

	schedule 5 secs { check_removed() };
}

event zeek_init() {
	# We need network time to be set to something other than zero for the
	# expiration time to be set correctly. Schedule an event on a short
	# timer so packets start getting read and do the setup there.
	schedule 100 msecs { setup_test() };
}
