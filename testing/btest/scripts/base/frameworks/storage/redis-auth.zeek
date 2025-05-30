# @TEST-DOC: Tests basic Redis storage backend functions in async mode

# @TEST-REQUIRES: have-redis
# @TEST-PORT: REDIS_PORT

# @TEST-EXEC: btest-bg-run redis-server run-redis-server ${REDIS_PORT%/tcp} testpassword
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: btest-bg-wait -k 0

# @TEST-EXEC: btest-diff out

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/redis

event zeek_init()
	{
	local opts: Storage::BackendOptions;
	opts$redis = [ $server_host="127.0.0.1", $server_port=to_port(getenv(
	    "REDIS_PORT")), $key_prefix="testing", $password="notthepassword" ];

	local key = "key1234";
	local value = "value5678";

	# This should fail because the password doesn't match.
	local res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_REDIS, opts, string, string);
	print "open 1", res;
	if ( res$code == Storage::SUCCESS )
		return;

	opts$redis$password = "testpassword";
	res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_REDIS, opts, string, string);
	print "open 2", res;

	if ( res$code != Storage::SUCCESS )
		return;

	local backend = res$value;
	res = Storage::Sync::close_backend(backend);
	print "close", res;
	}
