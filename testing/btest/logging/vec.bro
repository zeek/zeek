#
# @TEST-EXEC: bro %INPUT
# @TEST-EXEC: btest-diff ssh.log

module SSH;

export {
	redef enum Log::ID += { SSH };

	type Log: record {
        vec: vector of string &log;
	};
}

event bro_init()
{
	Log::create_stream(SSH, [$columns=Log]);

    local v: vector of string;

	v[1] = "2";
	v[4] = "5";

	Log::write(SSH, [$vec=v]);
}


