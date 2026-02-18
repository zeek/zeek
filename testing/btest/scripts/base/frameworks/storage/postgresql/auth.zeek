# @TEST-DOC: Tests basic PostgreSQL storage backend functions in async mode

# @TEST-REQUIRES: have-postgresql
# @TEST-PORT: POSTGRESQL_PORT

# @TEST-EXEC: btest-bg-run postgresql run-postgresql-server ${POSTGRESQL_PORT%/tcp} testing

# Give the server a couple of seconds to come up
# @TEST-EXEC: sleep 2

# @TEST-EXEC: zeek -b %INPUT | sed "s|, port ${POSTGRESQL_PORT%/tcp}|, port XXXX|g" > out
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
	local value = "value5678";

	# This should fail because the password doesn't match.
	local res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_POSTGRESQL, opts, string, string);

	# postgres-18 on macOS returns two error messages here. the first is a general
	# connection failure, and the second is an auth failure. on other systems, only
	# the auth failure is returned. find the auth failure in the messages so the test
	# is deterministic.
	print "open 1", res$code;

	if ( "no password" in res$error_str )
		print "open 1 result had auth error";

	if ( res$code == Storage::SUCCESS )
		return;

	opts$postgresql$connection_string=fmt("postgresql://:testing@localhost:%d/postgres", port_to_count(to_port(getenv("POSTGRESQL_PORT"))));
	res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_POSTGRESQL, opts, string, string);
	print "open 2", res;

	if ( res$code != Storage::SUCCESS )
		return;

	local backend = res$value;
	res = Storage::Sync::close_backend(backend);
	print "close", res;
	}
