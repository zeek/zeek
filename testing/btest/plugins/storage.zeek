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
	local put_res = Storage::put([$backend=b, $key=key, $value=value, $overwrite=F, $async_mode=F]);
	local get_res = Storage::get(b, key, F);
	if ( value != (get_res as string) ) {
		print("Got an invalid value in response!");
	}

	local erase_res = Storage::erase(b, key, F);
	get_res = Storage::get(b, key, F);
	Storage::close_backend(b);

	# Attempt to use the closed handle, which should report an error.
	get_res = Storage::get(b, key, F);

	# Test failing to open the handle and test closing an invalid handle.
	opts$open_fail = T;
	local b2 = Storage::open_backend(Storage::STORAGEDUMMY, opts, str, str);
	Storage::close_backend(b2);
}
