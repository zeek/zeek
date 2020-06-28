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

function my_rotation_format_func(ri: Log::RotationFmtInfo): Log::RotationPath
	{
	local open_str = strftime(Log::default_rotation_date_format, ri$open);
	local close_str = strftime(Log::default_rotation_date_format, ri$open);
	local prefix =fmt("%s__%s__%s__", ri$path, open_str, close_str);
	local rval = Log::RotationPath($file_prefix=prefix);
	return rval;
	}

redef Log::default_rotation_interval = 1hr;
redef Log::default_rotation_postprocessor_cmd = "echo 1st >>pp.log";
redef Log::rotation_format_func = my_rotation_format_func;

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
