# @TEST-EXEC: zeek %INPUT 2>&1 >output
# @TEST-EXEC: btest-diff output

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

# Manually control the clock.
redef allow_network_time_forward = F;

redef Storage::expire_interval = 1secs;

event zeek_init()
	{
	local opts = Storage::BackendOptions(
		$serializer=Storage::STORAGE_SERIALIZER_JSON,
		$sqlite=Storage::Backend::SQLite::Options(
			$database_path="test.sqlite",
			$table_name="testing"));

	local open_res = Storage::Sync::open_backend(
		Storage::STORAGE_BACKEND_SQLITE,
		opts,
		string,
		string);
	local h = open_res$value;

	local key="k";
	local value="v";

	# Expire entries well within `Storage::expire_interval` so `DoExpire` does not kick in.
	local expire = Storage::expire_interval / 10;
	local expire_time = network_time() + expire;
	Storage::Sync::put(
		h,
		Storage::PutArgs(
			$key=key,
			$value=value,
			$expire_time=expire));

	# The entry we just put in exists.
	local get = Storage::Sync::get(h, key);
	print "BEFORE", get;

	# Advance time.
	set_network_time(network_time() + expire * 2);

	# An expired value does not exist.
	get = Storage::Sync::get(h, key);
	print "AFTER", get;

	# Even though the entry still exists in the backend we can put a 
	# new value in its place without specifying overwrite.
	Storage::Sync::put(
		h,
		Storage::PutArgs(
			$key=key,
			$value=value+value));

	get = Storage::Sync::get(h, key);
	print "OVERWRITE", get;
	}
