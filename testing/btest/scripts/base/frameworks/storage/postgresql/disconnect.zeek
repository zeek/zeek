# @TEST-DOC: Tests basic PostgreSQL storage backend functions in sync mode, including overwriting

# @TEST-REQUIRES: have-postgresql
# @TEST-PORT: POSTGRESQL_PORT

# @TEST-EXEC: btest-bg-run postgresql run-postgresql-server ${POSTGRESQL_PORT%/tcp}

# Give the server a couple of seconds to come up
# @TEST-EXEC: sleep 2

# @TEST-EXEC: zeek -b %INPUT | sed "s|localhost:${POSTGRESQL_PORT%/tcp}|localhost:XXXX|g" > out

# @TEST-EXEC: btest-diff out

@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/postgresql

redef exit_only_after_terminate = T;

global b : opaque of Storage::BackendHandle;

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
	opts$postgresql = [ $connection_string=fmt("postgresql://localhost:%d/postgres?keepalives=1",
	                    port_to_count(to_port(getenv("POSTGRESQL_PORT")))),
	                    $table_name="testing" ];

	local key = "key1234";
	local value = "value1234";

	local open_res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_POSTGRESQL, opts, string, string);
	print "open_result", open_res;

	b = open_res$value;

	# Kill the postgresql server so the backend will disconnect and fire the backend_lost event.
	system("cat postgresql/.pid");
	system("kill $(cat postgresql/.pid)");

	# Sleep briefly for the keepalive timer to run out
	sleep(5sec);

	# Attempt to execute a command, which should fail because the server is dc'd.
	local put_res = Storage::Sync::put(b, [$key=key, $value=value]);
	print "put result", put_res;
	}
