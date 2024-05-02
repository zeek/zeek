#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff ssh.log

module SSH;

export {
	redef enum Log::ID += { LOG };

	type Log: record {
        List: list of string &log;
	};
}

event zeek_init()
{
	Log::create_stream(SSH::LOG, [$columns=Log]);

    local q: list of string;

	q += "2";
	q += "five";

	Log::write(SSH::LOG, [$List=q]);
}


