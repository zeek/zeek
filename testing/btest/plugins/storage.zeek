# @TEST-DOC: Basic test of a plugin implmenting a backend for the storage framework
# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"

# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Testing StorageDummy
# @TEST-EXEC: cp -r %DIR/storage-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=$(pwd) zeek -b Testing::StorageDummy %INPUT >> output 2>zeek-stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff zeek-stderr

@load base/frameworks/storage/sync

# Create a typename here that can be passed down into get().
type str: string;

type StorageDummyOpts : record {
	open_fail: bool;
};

redef record Storage::BackendOptions += {
	dummy: StorageDummyOpts &optional;
};

event zeek_init() {
	local opts : Storage::BackendOptions;
	opts$dummy = [$open_fail = F];

	local key = "key1234";
	local value = "value5678";

	# Test basic operation. The second get() should return an error
	# as the key should have been erased.
	local open_res = Storage::Sync::open_backend(Storage::STORAGEDUMMY, opts, str, str);
	print "open result", open_res;
	local b = open_res$value;
	local put_res = Storage::Sync::put(b, [$key=key, $value=value, $overwrite=F]);
	local get_res = Storage::Sync::get(b, key);
	if ( get_res$code != Storage::SUCCESS ) {
		print("Got an invalid value in response!");
	}

	local erase_res = Storage::Sync::erase(b, key);
	get_res = Storage::Sync::get(b, key);
	Storage::Sync::close_backend(b);

	if ( get_res$code != Storage::SUCCESS && get_res?$error_str )
		Reporter::error(get_res$error_str);

	# Test attempting to use the closed handle.
	put_res = Storage::Sync::put(b, [$key="a", $value="b", $overwrite=F]);
	get_res = Storage::Sync::get(b, "a");
	erase_res = Storage::Sync::erase(b, "a");

	print(fmt("results of trying to use closed handle: get: %s, put: %s, erase: %s",
	          get_res$code, put_res$code, erase_res$code));

	# Test failing to open the handle and test closing an invalid handle.
	opts$dummy$open_fail = T;
	open_res = Storage::Sync::open_backend(Storage::STORAGEDUMMY, opts, str, str);
	print "open result 2", open_res;
	local close_res = Storage::Sync::close_backend(open_res$value);
	print "close result of closed handle", close_res;
}
