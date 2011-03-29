#
# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: btest-diff ssh.log

module SSH;

export {
	redef enum Log::ID += { SSH };

	type Log: record {
		t: time;
		id: conn_id;
		status: string &optional &log;
		country: string &default="unknown" &log;
	};
}

redef Log += record {
	a1: count &log;
	a2: count;
};

redef Log += record {
	b1: count;
	b2: count;
} &log;


event bro_init()
{
	Log::create_stream(SSH, [$columns=Log]);

    local cid = [$orig_h=1.2.3.4, $orig_p=1234/tcp, $resp_h=2.3.4.5, $resp_p=80/tcp];

	Log::write(SSH, [$t=network_time(), $id=cid, $status="success", a1=1, a2=2, a3=3, a4=4]);
}

