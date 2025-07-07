# @TEST-DOC: Test metrics for storage/sqlite in a sync context
# @TEST-EXEC: zeek -b %INPUT > out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

@load base/frameworks/telemetry
@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

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

	Storage::Sync::close_backend(b);
	}

event zeek_init()
	{
	# Create a database file in the .tmp directory with a 'testing' table
	local opts: Storage::BackendOptions;
	opts$sqlite = [ $database_path="test.sqlite", $table_name="testing" ];

	local key = "key1234";
	local value = "value5678";

	# Test inserting/retrieving a key/value pair that we know won't be in
	# the backend yet.
	local res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_SQLITE, opts, string, string);
	print "open result", res;
	b = res$value;

	res = Storage::Sync::put(b, [$key=key, $value=value]);
	print "put result", res;

	res = Storage::Sync::get(b, key);
	print "get result 1", res;

	res = Storage::Sync::erase(b, key);
	print "erase result", res;

	local res2 = Storage::Sync::get(b, key);
	print "get result 2", res2;

	# Schedule this part for two reasons:
	# 1. To let the backend_opened event happen before we print metrics.
	# 2. To print the metrics before closing so that the page_count and file_size callbacks
	#    run before closing.
	schedule 100 msecs { print_metrics_and_close() };
	}
