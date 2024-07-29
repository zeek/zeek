# @TEST-DOC: Basic functionality for storage: opening/closing an sqlite backend, storing/retrieving/erasing basic data
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out

@load base/frameworks/storage

# Create a typename here that can be passed down into open_backend.
type str: string;

event zeek_init() {
	# Create a database file in the .tmp directory with a 'testing' table
	local opts : Storage::SqliteOptions;
	opts$database_path = "test.sqlite";
	opts$table_name = "testing";

	local key = "key1111";
	local value = "value";

	local b = Storage::open_backend(Storage::SQLITE, opts, str);
	local res = Storage::store(b, key, value, T);
	print res;

	local res2 = Storage::retrieve(b, key);
	print res2;

	Storage::erase(b, key);
	Storage::close_backend(b);
}
