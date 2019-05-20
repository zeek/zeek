#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff testing.log

@load tuning/json-logs

module testing;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log &optional;
        msg: string &log &optional;
    };

    global log_test: event(rec: Info);
}

event zeek_init() &priority=5
{
    Log::create_stream(testing::LOG, [$columns=testing::Info, $ev=log_test]);
    local info: Info;
    info$msg = "Testing 1 2 3 ";
   Log::write(testing::LOG, info);
}

