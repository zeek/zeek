# @TEST-DOC: Basic test of a plugin implmenting a backend for the storage framework
# @TEST-REQUIRES: test "${ZEEK_ZAM}" != "1"

# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Testing StorageDummy
# @TEST-EXEC: cp -r %DIR/storage-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=$(pwd) zeek -b Testing::StorageDummy %INPUT >> output 2>zeek-stderr
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff zeek-stderr

@load base/frameworks/storage/sync

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

	# Basic operation. Open, put, and get the value back.
	local res = Storage::Sync::open_backend(Storage::STORAGEDUMMY, opts, string, string);
	print "open result", res;
	local b = res$value;

	res = Storage::Sync::put(b, [$key=key, $value=value, $overwrite=F]);
	print "put result", res;

	res = Storage::Sync::get(b, key);
	print "get result", res;
	if ( res$code == Storage::SUCCESS && res?$value )
		print "get result same as inserted", value == (res$value as string);
	print "";

	# Erase the key and attempt to get it back.
	res = Storage::Sync::erase(b, key);
	print "erase result", res;
	res = Storage::Sync::get(b, key);
	print "get result after erase", res;
	print "";

	# Close the handle and test trying to use the closed handle.
	res = Storage::Sync::close_backend(b);
	print "close result", res;

	# Test attempting to use the closed handle.
	local put_res = Storage::Sync::put(b, [$key="a", $value="b", $overwrite=F]);
	local get_res = Storage::Sync::get(b, "a");
	local erase_res = Storage::Sync::erase(b, "a");

	print(fmt("results of trying to use closed handle: get: %s, put: %s, erase: %s",
	          get_res$code, put_res$code, erase_res$code));
	print "";

	# Test failing to open the handle and test closing an invalid handle.
	opts$dummy = [$open_fail = T];
	res = Storage::Sync::open_backend(Storage::STORAGEDUMMY, opts, string, string);
	print "open result 2", res;
	res = Storage::Sync::close_backend(res$value);
	print "close result on closed handle", res;
}
