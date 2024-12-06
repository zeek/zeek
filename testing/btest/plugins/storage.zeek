# @TEST-DOC: Basic test of a plugin implmenting a backend for the storage framework
# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Testing StorageDummy
# @TEST-EXEC: cp -r %DIR/storage-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=$(pwd) zeek -b Testing::StorageDummy %INPUT >> output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff .stderr

@load base/frameworks/storage

# Create a typename here that can be passed down into get().
type str: string;

type StorageDummyOpts : record {
	open_fail: bool;
};

event zeek_init() {
	local opts : StorageDummyOpts;
	opts$open_fail = F;

	local key = "key1234";
	local value = "value5678";

	# Test basic operation. The second get() should return an error
	# as the key should have been erased.
	local b = Storage::open_backend(Storage::STORAGEDUMMY, opts, str, str);
	local put_res = Storage::put(b, key, value, F);
	local get_res = Storage::get(b, key);
	if ( get_res is bool ) {
		print("Got an invalid value in response!");
	}

	local erase_res = Storage::erase(b, key);
	get_res = Storage::get(b, key);
	Storage::close_backend(b);

	# Test attempting to use the closed handle.
	put_res = Storage::put(b, "a", "b", F);
	get_res = Storage::get(b, "a");
	erase_res = Storage::erase(b, "a");

	# Test failing to open the handle and test closing an invalid handle.
	opts$open_fail = T;
	local b2 = Storage::open_backend(Storage::STORAGEDUMMY, opts, str, str);
	Storage::close_backend(b2);
}
