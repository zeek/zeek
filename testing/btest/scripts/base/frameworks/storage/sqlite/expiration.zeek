# @TEST-DOC: Automatic expiration of stored data
# TODO: This test hangs indefinitely on Windows and is skipped for the time being.
# @TEST-REQUIRES: ! is-windows
#
# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek -b -r - %INPUT > out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

redef Storage::expire_interval = 2 secs;
redef exit_only_after_terminate = T;

global b: opaque of Storage::BackendHandle;
global key1: string = "key1234";
global value1: string = "value1234";

global key2: string = "key2345";
global value2: string = "value2345";

global key3: string = "key3456";
global value3: string = "value3456";

event check_removed()
	{
	local res = Storage::Sync::get(b, key1);
	print "get result 1 after expiration", res;

	res = Storage::Sync::get(b, key2);
	print "get result 2 after expiration", res;

	res = Storage::Sync::get(b, key3);
	print "get result 3 after expiration", res;

	Storage::Sync::close_backend(b);
	terminate();
	}

event setup_test()
	{
	local opts : Storage::BackendOptions;
	opts$sqlite = [$database_path = "storage-test.sqlite", $table_name = "testing"];

	local open_res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_SQLITE, opts, string, string);
	print "open result", open_res;

	b = open_res$value;

	# Insert a key that will expire in the time allotted
	local res = Storage::Sync::put(b, [ $key=key1, $value=value1, $expire_time=2secs ]);
	print "put result 1", res;

	# Insert a key that won't expire
	res = Storage::Sync::put(b, [ $key=key2, $value=value2, $expire_time=20secs ]);
	print "put result 2", res;

	# Insert a key that should expire and then overwrite it with a new expiration time to
	# set it to something that won't expire to verify that expiration gets reset.
	res = Storage::Sync::put(b, [ $key=key3, $value=value3, $expire_time=2secs ]);
	print "put result 3.1", res;

	res = Storage::Sync::put(b, [ $key=key3, $value=value3, $expire_time=25secs, $overwrite=T ]);
	print "put result 3.2", res;

	res = Storage::Sync::get(b, key1);
	print "get result", res;
	if ( res$code == Storage::SUCCESS && res?$value )
		print "get result same as inserted", value1 == ( res$value as string );

	res = Storage::Sync::get(b, key2);
	print "get result 2", res;
	if ( res$code == Storage::SUCCESS && res?$value )
		print "get result 2 same as inserted", value2 == ( res$value as string );

	res = Storage::Sync::get(b, key3);
	print "get result 3", res;
	if ( res$code == Storage::SUCCESS && res?$value )
		print "get result 3 same as inserted", value3 == ( res$value as string );

	schedule 5secs { check_removed() };
	}

event zeek_init()
	{
	# We need network time to be set to something other than zero for the
	# expiration time to be set correctly. Schedule an event on a short
	# timer so packets start getting read and do the setup there.
	schedule 100msecs { setup_test() };
	}
