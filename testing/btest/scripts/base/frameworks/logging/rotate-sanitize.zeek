# @TEST-EXEC: zeek -b -r ${TRACES}/rotation.trace %INPUT
# @TEST-EXEC-FAIL: test -f must-not-exist

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

redef Log::default_rotation_interval = 1hr;
redef Log::default_rotation_postprocessor_cmd = "echo";

event zeek_init()
{
	Log::create_stream(Test::LOG, [$columns=Log, $path="; touch must-not-exist; true "]);
}

event new_connection(c: connection)
	{
	Log::write(Test::LOG, [$t=network_time(), $id=c$id]);
	}
