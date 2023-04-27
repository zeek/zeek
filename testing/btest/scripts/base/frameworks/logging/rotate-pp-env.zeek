# @TEST-DOC: Using a custom environment for the postprocessor command.
# @TEST-EXEC: ZEEK_ARG_EXTERNAL=external zeek -b -r ${TRACES}/rotation.trace %INPUT >out 2>&1
# @TEST-EXEC: btest-diff out

module Test;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		t: time;
		id: conn_id;
	} &log;
}

redef Log::default_rotation_interval = 1hr;
redef Log::default_rotation_postprocessor_cmd = "env | grep ZEEK_ARG | sort; true ";

redef Log::default_rotation_postprocessor_cmd_env += {
	["REDEF"] = "redef",
};

event zeek_init()
	{
	Log::create_stream(Test::LOG, [$columns=Log]);
	Log::default_rotation_postprocessor_cmd_env["INIT"] = "zeek_init";
	}

event new_connection(c: connection)
	{
	Log::write(Test::LOG, [$t=network_time(), $id=c$id]);
	}
