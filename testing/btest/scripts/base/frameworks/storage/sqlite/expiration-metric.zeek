# @TEST-DOC: The expired-entries metric counts the rows that expiration removed.
#
# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek -b -r - %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

@load base/frameworks/storage/sync
@load base/frameworks/telemetry
@load policy/frameworks/storage/backend/sqlite

redef Storage::expire_interval = 2 secs;
redef exit_only_after_terminate = T;

global b: opaque of Storage::BackendHandle;

function expired_entries(): double
	{
	local metrics = Telemetry::collect_metrics("zeek", "storage_backend_expired_entries");
	for ( i in metrics )
		return metrics[i]$value;

	return -1.0;
	}

# Expiration runs on its own thread, so poll until it has removed the entries.
# The trace ends about 6.5 seconds after the setup, after which network time
# doesn't advance anymore.
event check_metric(attempts_left: count)
	{
	local n = expired_entries();

	if ( n == 0.0 && attempts_left > 0 )
		{
		schedule 100 msecs { check_metric(attempts_left - 1) };
		return;
		}

	print "expired entries", n;
	Storage::Sync::close_backend(b);
	terminate();
	}

event setup_test()
	{
	local opts: Storage::BackendOptions;
	opts$sqlite = [$database_path="storage-test.sqlite", $table_name="testing"];
	b = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_SQLITE, opts, string, string)$value;

	# Three entries that expire, and one that doesn't.
	Storage::Sync::put(b, [$key="a", $value="1", $expire_time=2 secs]);
	Storage::Sync::put(b, [$key="b", $value="2", $expire_time=2 secs]);
	Storage::Sync::put(b, [$key="c", $value="3", $expire_time=2 secs]);
	Storage::Sync::put(b, [$key="d", $value="4", $expire_time=60 secs]);

	# Expiration runs every 2 seconds; the entries above are expired by the
	# second run, about 4 seconds from now.
	schedule 3 secs { check_metric(30) };
	}

event zeek_init()
	{
	# Network time must be set for expiration times to be correct, so do the
	# setup once packets are being read.
	schedule 100 msecs { setup_test() };
	}
