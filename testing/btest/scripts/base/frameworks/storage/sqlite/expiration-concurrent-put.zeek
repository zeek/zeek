# @TEST-DOC: Async puts that overlap with the expiration thread's transaction wait for the lock instead of failing immediately as timeouts.
#
# @TEST-EXEC: zeek -b -r $TRACES/smtp.pcap %INPUT > out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff .stderr

@load base/frameworks/storage/async
@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

# Start an expiration run on (nearly) every packet, and give every entry a
# short expiration so that the runs have rows to delete. This makes the
# expiration thread hold its write transaction while the puts below run.
redef Storage::expire_interval = 1 msec;

global backend: opaque of Storage::BackendHandle;
global puts = 0;
global results: table[string] of count &default=0 &ordered;

event zeek_init()
	{
	local opts: Storage::BackendOptions;
	opts$sqlite = [$database_path="test.sqlite", $table_name="testing"];

	local res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_SQLITE, opts, string, count);
	if ( res$code != Storage::SUCCESS )
		{
		print "open failed", res;
		return;
		}

	backend = res$value;
	}

event new_packet(c: connection, p: pkt_hdr)
	{
	local i = 0;
	while ( i < 5 )
		{
		++puts;
		local key = cat(puts);

		when [key] ( local res = Storage::Async::put(backend, [$key=key, $value=1,
		                                                      $expire_time=1 msec]) )
			{
			++results[cat(res$code)];
			}
		timeout 1 hr
			{
			++results["when timeout"];
			}

		++i;
		}
	}

event zeek_done()
	{
	print "puts", puts;
	for ( r, n in results )
		print r, n;
	}
