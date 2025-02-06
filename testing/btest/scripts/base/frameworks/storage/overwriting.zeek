# @TEST-DOC: Overwriting existing data in a SQLite backend
# @TEST-EXEC: cp $FILES/storage-test.sqlite ./storage-test.sqlite
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

# Create a typename here that can be passed down into get().
type str: string;

event zeek_init() {
	local opts : Storage::BackendOptions;
	opts$sqlite = [$database_path = "storage-test.sqlite", $table_name = "testing"];

	local key = "key1234";
	local value = "value7890";

	local b = Storage::Sync::open_backend(Storage::SQLITE, opts, str, str);

	local res = Storage::Sync::put(b, [$key=key, $value=value]);
	print "put result", res;

	local res2 = Storage::Sync::get(b, key);
	print "get result", res2;
	if ( res2?$val )
		print "get result same as inserted", value == (res2$val as string);

	Storage::Sync::close_backend(b);
}
