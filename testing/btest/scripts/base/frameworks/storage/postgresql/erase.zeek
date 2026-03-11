# @TEST-DOC: Tests basic PostgreSQL storage backend functions in sync mode, including overwriting

# @TEST-REQUIRES: have-postgresql
# @TEST-PORT: POSTGRESQL_PORT

# @TEST-EXEC: btest-bg-run postgresql run-postgresql-server ${POSTGRESQL_PORT%/tcp}

# Give the server a couple of seconds to come up
# @TEST-EXEC: sleep 2

# @TEST-EXEC: zeek -b %INPUT | sed 's|=[0-9]*/tcp|=xxxx/tcp|g' > out
# @TEST-EXEC: btest-bg-wait -k 0

# @TEST-EXEC: btest-diff out

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/postgresql

event zeek_init()
	{
	local opts: Storage::BackendOptions;
	opts$postgresql = [ $connection_string=fmt("postgresql://localhost:%d/postgres",
	                    port_to_count(to_port(getenv("POSTGRESQL_PORT")))),
	                    $table_name="testing" ];

	local key = "key1234";
	local value = "value1234";

	local open_res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_POSTGRESQL, opts, string, string);
	print "open_result", open_res;

	local b = open_res$value;

	local res = Storage::Sync::put(b, [ $key=key, $value=value ]);
	print "put result", res;

	res = Storage::Sync::get(b, key);
	print "get result", res;
	if ( res$code == Storage::SUCCESS && res?$value )
		print "get result same as inserted", value == ( res$value as string );

	res = Storage::Sync::erase(b, key);
	print "erase result", res;

	res = Storage::Sync::get(b, key);
	if ( res$code != Storage::SUCCESS )
		print "get result 2", res;

	Storage::Sync::close_backend(b);
	}
