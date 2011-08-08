#
# @TEST-EXEC: bro -b -r %DIR/rotation.trace %INPUT | egrep "test|test2" | sort >out
# @TEST-EXEC: for i in `ls test*.log | sort`; do printf '> %s\n' $i; cat $i; done | sort | uniq >>out
# @TEST-EXEC: btest-diff out

module Test;

export {
	# Create a new ID for our log stream
	redef enum Log::ID += { Test };

	# Define a record with all the columns the log file can have.
	# (I'm using a subset of fields from ssh-ext for demonstration.)
	type Log: record {
		t: time;
		id: conn_id; # Will be rolled out into individual columns.
	} &log;
}

redef Log::default_rotation_interval = 1hr;
redef Log::default_rotation_postprocessor = "echo 1st";

redef Log::rotation_control += {
	[Log::WRITER_ASCII, "test2"] = [$interv=30mins, $postprocessor="echo 2nd"]
};

event bro_init()
{
	Log::create_stream(Test, [$columns=Log]);
	Log::add_filter(Test, [$name="2nd", $path="test2"]);

}

event new_connection(c: connection)
	{
	Log::write(Test, [$t=network_time(), $id=c$id]);
	}
