# @TEST-DOC: Overwriting existing data in a SQLite backend
# @TEST-EXEC: cp $FILES/storage-test.sqlite ./storage-test.sqlite
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

event zeek_init() {
	local opts : Storage::BackendOptions;
	opts$sqlite = [$database_path = "storage-test.sqlite", $table_name = "testing"];

	local key = "key1234";
	local value = "value7890";

	local open_res = Storage::Sync::open_backend(Storage::SQLITE, opts, string, string);
	print "open result", open_res;
	local b = open_res$value;

	local res = Storage::Sync::put(b, [$key=key, $value=value]);
	print "put result", res;

	local res2 = Storage::Sync::get(b, key);
	print "get result", res2;
	if ( res2$code == Storage::SUCCESS && res2?$value )
		print "get result same as inserted", value == (res2$value as string);

	Storage::Sync::close_backend(b);
}
