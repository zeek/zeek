#
# @TEST-EXEC: zeek -b -r ${TRACES}/rotation.trace %INPUT | egrep "test|test2" | sort >out.tmp
# @TEST-EXEC: cat out.tmp pp.log | sort >out
# @TEST-EXEC: for i in `ls test*.log | sort`; do printf '> %s\n' $i; cat $i; done | sort | $SCRIPTS/diff-remove-timestamps | uniq >>out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff .stderr

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
redef Log::default_rotation_postprocessor_cmd = "echo 1st >>pp.log";

function custom_rotate(info: Log::RotationInfo) : bool
{
    print "custom rotate", info;
    return T;
}

event zeek_init()
{
	Log::create_stream(Test::LOG, [$columns=Log]);
	Log::add_filter(Test::LOG, [$name="2nd", $path="test2", $interv=30mins, $postprocessor=custom_rotate]);
}

event new_connection(c: connection)
	{
	Log::write(Test::LOG, [$t=network_time(), $id=c$id]);
	}
