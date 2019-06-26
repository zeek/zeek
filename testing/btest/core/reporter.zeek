#
# @TEST-EXEC: zeek %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff logger-test.log

event zeek_init()
{
    Reporter::info("init test-info");
    Reporter::warning("init test-warning");
    Reporter::error("init test-error");
}

event zeek_done()
{
    Reporter::info("done test-info");
    Reporter::warning("done test-warning");
    Reporter::error("done test-error");
}

global first = 1;

event connection_established(c: connection)
{
    if ( ! first )
        return;

    print "established";
    
    Reporter::info("processing test-info");
    Reporter::warning("processing test-warning");
    Reporter::error("processing test-error");
    first = 0;
}

global f = open_log_file("logger-test");

event reporter_info(t: time, msg: string, location: string)
	{
    print f, fmt("reporter_info|%s|%s|%.6f", msg, location, t);
    }

event reporter_warning(t: time, msg: string, location: string)
	{
    print f, fmt("reporter_warning|%s|%s|%.6f", msg, location, t);
    }

event reporter_error(t: time, msg: string, location: string)
	{
    print f, fmt("reporter_error|%s|%s|%.6f", msg, location, t);
    }

Reporter::info("pre test-info");
Reporter::warning("pre test-warning");
Reporter::error("pre test-error");

