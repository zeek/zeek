#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: cat ssh.log | grep -v PREFIX.*20..- >ssh-filtered.log
# @TEST-EXEC: btest-diff ssh-filtered.log

redef LogAscii::output_to_stdout = F;
redef LogAscii::separator = "|";
redef LogAscii::empty_field = "EMPTY";
redef LogAscii::unset_field = "NOT-SET";
redef LogAscii::meta_prefix = "PREFIX<>";

module SSH;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		t: time;
		id: conn_id; # Will be rolled out into individual columns.
		status: string &optional;
		country: string &default="unknown";
		b: bool &optional;
	} &log;
}

event zeek_init()
{
	Log::create_stream(SSH::LOG, [$columns=Log]);

    local cid = [$orig_h=1.2.3.4, $orig_p=1234/tcp, $resp_h=2.3.4.5, $resp_p=80/tcp];

	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="success"]);
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $country="US"]);
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="failure", $country="UK"]);
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $country="BR"]);
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $b=T, $status="failure", $country=""]);
	
}

