# @TEST-EXEC: zeek %INPUT 2>&1 >output
# @TEST-EXEC: btest-diff output

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

redef Storage::expire_interval = 1secs;

event zeek_init()
	{
	local opts = Storage::BackendOptions(
		$serializer=Storage::STORAGE_SERIALIZER_JSON,
		$sqlite=Storage::Backend::SQLite::Options(
			$database_path="test.sqlite",
			$table_name="testing"));

	local key = "k";
	local value = "v";

	local open_res = Storage::Sync::open_backend(
		Storage::STORAGE_BACKEND_SQLITE,
		opts,
		string,
		string);
	local h = open_res$value;

	# Expire entries well within `Storage::expire_interval` so `DoExpire` does not kick in.
	local expire = Storage::expire_interval / 10;
	local expire_time = current_time() + expire;
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
	sleep(expire);
	set_network_time(current_time());

	# An expired value does not exist.
	get = Storage::Sync::get(h, key);
	print "AFTER", get;
	}
