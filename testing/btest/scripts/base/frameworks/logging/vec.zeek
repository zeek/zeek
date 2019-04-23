#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff ssh.log

module SSH;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
        vec: vector of string &log;
	};
}

event zeek_init()
{
	Log::create_stream(SSH::LOG, [$columns=Log]);

    local v: vector of string;

	v[1] = "2";
	v[4] = "5";

	Log::write(SSH::LOG, [$vec=v]);
}


