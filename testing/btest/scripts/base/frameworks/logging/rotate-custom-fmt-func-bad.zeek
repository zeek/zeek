# @TEST-DOC: A non-behaving rotation_format_func could cause segfaults by not returning a value. Cover this.
# @TEST-EXEC: zeek -b -r ${TRACES}/rotation.trace %INPUT
# @TEST-EXEC: ls test*log | sort >> out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

module Test;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		t: time;
		id: conn_id;
	} &log;
}

global rotation_count: table[string] of count &default = 0;

# Custom Log::rotation_format_func that triggers two errors:
# * Returning nil/no value
# * Divide by zero
#
# The logging Manager should cover either case and fall back
# to a fixed format.
function my_rotation_format_func(ri: Log::RotationFmtInfo): Log::RotationPath
	{
	local c = rotation_count[ri$path] + 1;
	rotation_count[ri$path] = c;

	if ( ri$path == "test" && c == 4 )
		print "do nothing";  # returns nil
	else if ( ri$path == "test" && c == 8 )
		return [$file_basename=fmt("%s-%s", ri$path, c / 0)];  # divide by zero
	else
		return [$file_basename=fmt("%s-%s", ri$path, c)];
	}

redef Log::default_rotation_interval = 1hr;
redef Log::rotation_format_func = my_rotation_format_func;

event zeek_init()
	{
	Log::create_stream(Test::LOG, [$columns=Log]);
	}

event new_connection(c: connection)
	{
	Log::write(Test::LOG, [$t=network_time(), $id=c$id]);
	}
