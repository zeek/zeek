# @TEST-DOC: Tests various error handling scenarios for the storage framework

# @TEST-REQUIRES: have-redis
# @TEST-PORT: REDIS_PORT

# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

@load base/frameworks/storage/sync
@load base/frameworks/reporter
@load policy/frameworks/storage/backend/redis

event zeek_init() {
	# Test failing to connect to a server
	local opts : Storage::BackendOptions;
	opts$redis = [ $server_host="127.0.0.1", $server_port=to_port(getenv(
	    "REDIS_PORT")), $key_prefix="testing" ];

	local res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_REDIS, opts, string, string);

	# macOS says this is a timeout, but linux says it's a connection refused. The
	# error string in the record contains the full reason, so don't print out the full
	# record in the interest of test determinism.
	if ( res$code == Storage::CONNECTION_FAILED )
		print "Failed to connect";
}
