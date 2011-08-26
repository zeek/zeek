# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

module Test;

export {
	redef enum Log::ID += { Test };

	type Info: record {
		t: time;
		id: conn_id;
	} &log;
}

function custom_rotate(info: Log::RotationInfo) : bool
{
    print "custom rotate", info;
    return T;
}

event bro_init()
{
	Log::create_stream(Test, [$columns=Info]);
	Log::add_filter(Test, [$name="2nd", $path="test2",
	    $rotation=[$interv=30mins, $postprocessor=custom_rotate]]);
	print Log::rotation_control;
	Log::remove_filter(Test, "2nd");
	# The RotationControl should be removed now
	print Log::rotation_control;
}
