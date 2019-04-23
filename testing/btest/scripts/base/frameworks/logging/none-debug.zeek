#
# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

redef Log::default_writer = Log::WRITER_NONE;
redef LogNone::debug = T;
redef Log::default_rotation_interval= 1hr;
redef log_rotate_base_time = "00:05";

module SSH;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		t: time;
		id: conn_id; # Will be rolled out into individual columns.
		status: string &optional;
		country: string &default="unknown";
	} &log;
}

event zeek_init()
{
        local config: table[string] of string;
        config["foo"]="bar";
        config["foo2"]="bar2";

	local cid = [$orig_h=1.2.3.4, $orig_p=1234/tcp, $resp_h=2.3.4.5, $resp_p=80/tcp];

	Log::create_stream(SSH::LOG, [$columns=Log]);

	Log::remove_default_filter(SSH::LOG);
	Log::add_filter(SSH::LOG, [$name="f1", $exclude=set("t", "id.orig_h"), $config=config]);
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="success"]);
}

