# @TEST-DOC: Tests that PostgreSQL storage backend defaults back to sync mode reading pcaps

# @TEST-REQUIRES: have-postgresql
# @TEST-PORT: POSTGRESQL_PORT

# @TEST-EXEC: btest-bg-run postgresql run-postgresql-server ${POSTGRESQL_PORT%/tcp}

# Give the server a couple of seconds to come up
# @TEST-EXEC: sleep 2

# @TEST-EXEC: zeek -r $TRACES/http/get.trace -b %INPUT > out
# @TEST-EXEC: btest-bg-wait -k 0

# @TEST-EXEC: btest-diff out

@load base/frameworks/storage/sync
@load base/frameworks/storage/async
@load policy/frameworks/storage/backend/postgresql

event zeek_init()
	{
	local opts: Storage::BackendOptions;
	opts$postgresql = [ $connection_string=fmt("postgresql://localhost:%d/postgres",
	                    port_to_count(to_port(getenv("POSTGRESQL_PORT")))),
	                    $table_name="testing" ];

	local key = "key1234";
	local value = "value5678";

	local open_res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_POSTGRESQL, opts, string, string);
	print "open result", open_res;
	local b = open_res$value;

	when [b, key, value] ( local res = Storage::Async::put(b, [ $key=key,
	    $value=value ]) )
		{
		print "put result", res;

		when [b, key, value] ( local res2 = Storage::Async::get(b, key) )
			{
			print "get result", res2;
			if ( res2$code == Storage::SUCCESS && res2?$value )
				print "get result same as inserted", value == ( res2$value as string );

			Storage::Sync::close_backend(b);
			}
		timeout 5sec
			{
			print "get request timed out";
			}
		}
	timeout 5sec
		{
		print "put request timed out";
		}
	}
