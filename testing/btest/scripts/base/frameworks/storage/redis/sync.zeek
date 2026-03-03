# @TEST-DOC: Tests basic Redis storage backend functions in sync mode, including overwriting

# @TEST-REQUIRES: have-redis
# @TEST-PORT: REDIS_PORT

# @TEST-EXEC: btest-bg-run redis-server run-redis-server ${REDIS_PORT%/tcp}
# @TEST-EXEC: zeek -b %INPUT | sed 's|=[0-9]*/tcp|=XXXX/tcp|g' | sed "s|-${REDIS_PORT%/tcp}-|-XXXX-|g" > out
# @TEST-EXEC: btest-bg-wait -k 0

# @TEST-EXEC: btest-diff out

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/redis
@load base/frameworks/telemetry

# Make sure the telemetry output is in a fixed order.
redef running_under_test = T;

global b : opaque of Storage::BackendHandle;

event print_metrics_and_close()
	{
	print "";
	print "Post-operation metrics:";
	local storage_metrics = Telemetry::collect_metrics("zeek", "storage*");
	for (i in storage_metrics)
		{
		local m = storage_metrics[i];
		print m$opts$metric_type, m$opts$prefix, m$opts$name, m$label_names, m$label_values, m$value;
		}
	print "";

	Storage::Sync::close_backend(b);
	}

event Storage::backend_opened(tag: Storage::Backend, config: any) {
	print "Storage::backend_opened", tag, config;
}

event Storage::backend_lost(tag: Storage::Backend, config: any, reason: string) {
	print "Storage::backend_lost", tag, config, reason;
	terminate();
}

event zeek_init()
	{
	local opts: Storage::BackendOptions;
	opts$serializer = Storage::STORAGE_SERIALIZER_JSON;
	opts$redis = [ $server_host="127.0.0.1", $server_port=to_port(getenv(
	    "REDIS_PORT")), $key_prefix="testing" ];

	local key = "key1234";
	local value = "value1234";
	local value2 = "value2345";

	local res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_REDIS, opts, string, string);
	print "open_result", res;

	b = res$value;

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

	# Attempt to get a value that doesn't exist.
	res = Storage::Sync::get(b, "testing");
	print "get result", res;

	schedule 100 msec { print_metrics_and_close() };
	}
