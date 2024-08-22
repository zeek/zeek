# @TEST-DOC: Overwriting existing data in a SQLite backend
# @TEST-EXEC: cp $FILES/storage-test.sqlite ./storage-test.sqlite
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

@load base/frameworks/storage

# Create a typename here that can be passed down into get().
type str: string;

event zeek_init() {
	local opts : Storage::SqliteOptions;
	opts$database_path = "storage-test.sqlite";
	opts$table_name = "testing";

	local key = "key1234";
	local value = "value7890";

	local b = Storage::open_backend(Storage::SQLITE, opts);

	local res = Storage::put(b, key, value, T, 0sec, F);
	print "put result", res;

	local res2 = Storage::get(b, key, str, F);
	print "get result", res2;
	print "get result same as inserted", value == (res2 as string);

	Storage::close_backend(b);
}
