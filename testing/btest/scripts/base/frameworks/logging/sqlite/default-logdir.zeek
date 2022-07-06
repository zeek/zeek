#
# @TEST-REQUIRES: which sqlite3
# @TEST-REQUIRES: has-writer Zeek::SQLiteWriter
# @TEST-GROUP: sqlite
#
# @TEST-EXEC: mkdir logs
# @TEST-EXEC: zeek -b -r ${TRACES}/rotation.trace %INPUT >zeek.out 2>&1
# @TEST-EXEC: sqlite3 ./logs/test.sqlite 'select * from test' > test.select
# @TEST-EXEC: btest-diff test.select
# @TEST-EXEC: btest-diff zeek.out
#
# @TEST-DOC: Configure Log::default_writer, Log::default_logdir and ensure the test.sqlite database is in ./logs

redef Log::default_writer = Log::WRITER_SQLITE;
redef Log::default_logdir = "./logs";

# Also enable log-rotation, but it has no effect on sqlite.
redef Log::default_rotation_interval = 1hr;
redef Log::default_rotation_postprocessor_cmd = "echo";

redef LogSQLite::unset_field = "(unset)";

module Test;

export {
	# Create a new ID for our log stream
	redef enum Log::ID += { LOG };

	# Define a record with all the columns the log file can have.
	# (I'm using a subset of fields from ssh-ext for demonstration.)
	type Log: record {
		t: time;
		id: conn_id; # Will be rolled out into individual columns.
	} &log;
}
event zeek_init()
	{
	Log::create_stream(Test::LOG, [$columns=Log]);
	}

event new_connection(c: connection)
	{
	Log::write(Test::LOG, [$t=network_time(), $id=c$id]);
	}
