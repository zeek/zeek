#
# @TEST-EXEC: bro %INPUT >output 2>&1
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff logger-test.log

event bro_init()
{
    Log::message("init test-message");
    Log::warning("init test-warning");
    Log::error("init test-error");
}

event bro_done()
{
    Log::message("done test-message");
    Log::warning("done test-warning");
    Log::error("done test-error");
}

global first = 1;

event connection_established(c: connection)
{
    if ( ! first )
        return;

    print "established";
    
    Log::message("processing test-message");
    Log::warning("processing test-warning");
    Log::error("processing test-error");
    first = 0;
}

global f = open_log_file("logger-test");

event log_message(t: time, msg: string, location: string)
	{
    print f, fmt("log_message|%s|%s|%.6f", msg, location, t);
    }

event log_warning(t: time, msg: string, location: string)
	{
    print f, fmt("log_warning|%s|%s|%.6f", msg, location, t);
    }

event log_error(t: time, msg: string, location: string)
	{
    print f, fmt("log_error|%s|%s|%.6f", msg, location, t);
    }

Log::message("pre test-message");
Log::warning("pre test-warning");
Log::error("pre test-error");

