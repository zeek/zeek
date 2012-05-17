#
# @TEST-REQUIRES: has-writer DataSeries && which ds2txt
# @TEST-GROUP: dataseries
#
# @TEST-EXEC: bro -b -r ${TRACES}/rotation.trace %INPUT 2>&1 Log::default_writer=Log::WRITER_DATASERIES | grep "test" >out
# @TEST-EXEC: for i in test.*.ds; do printf '> %s\n' $i; ds2txt --skip-index $i; done >>out
# @TEST-EXEC: btest-diff out

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

event bro_init()
{
	Log::create_stream(Test::LOG, [$columns=Log]);
}

event new_connection(c: connection)
	{
	Log::write(Test::LOG, [$t=network_time(), $id=c$id]);
	}
