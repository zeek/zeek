#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff ssh.log

module SSH;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		t: time;
		id: conn_id;
		status: string &optional &log;
		country: string &default="unknown" &log;
	};
}

redef record Log += {
	a1: count &log &optional;
	a2: count &optional;
};

redef record Log += {
	b1: count &optional;
	b2: count &optional;
} &log;


event zeek_init()
{
	Log::create_stream(SSH::LOG, [$columns=Log]);

    local cid = [$orig_h=1.2.3.4, $orig_p=1234/tcp, $resp_h=2.3.4.5, $resp_p=80/tcp];

	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="success", $a1=1, $a2=2, $b1=3, $b2=4]);
}

