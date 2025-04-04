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
	opts$sqlite = [$database_path = "testing.sqlite", $table_name = "testing"];

	local key = "key1111";
	local value = "value7890";
	local value2 = "value2345";

	local res = Storage::Sync::open_backend(Storage::SQLITE, opts, str, str);
	print "open result", res;
	local b = res$value;

	# Put a first value. This should return Storage::SUCCESS.
	res = Storage::Sync::put(b, [$key=key, $value=value]);
	print "put result", res;

	# Get the first value, validate that it's what we inserted.
	res = Storage::Sync::get(b, key);
	print "get result", res;
	if ( res$code == Storage::SUCCESS && res?$value )
		print "get result same as inserted", value == (res$value as string);

	# This will return a Storage::KEY_EXISTS since we don't want overwriting.
	res = Storage::Sync::put(b, [$key=key, $value=value2, $overwrite=F]);
	print "put result", res;

	# Verify that the overwrite didn't actually happen.
	res = Storage::Sync::get(b, key);
	print "get result", res;
	if ( res$code == Storage::SUCCESS && res?$value )
		print "get result same as originally inserted", value == (res$value as string);

	# This will return a Storage::SUCESSS since we're asking for an overwrite.
	res = Storage::Sync::put(b, [$key=key, $value=value2, $overwrite=T]);
	print "put result", res;

	# Verify that the overwrite happened.
	res = Storage::Sync::get(b, key);
	print "get result", res;
	if ( res$code == Storage::SUCCESS && res?$value )
		print "get result same as overwritten", value2 == (res$value as string);

	Storage::Sync::close_backend(b);
}
