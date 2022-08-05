# @TEST-DOC: Redef'ing of record fields for adding and removing &log from them.
# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff test.log

module RedefRecordTest;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                ts: time &log;
                msg: string &log;
                extra1: string &log &optional;
                extra2: string &optional;
                extra3: string &optional;
                extra4: string &optional;
        };
}

# Adding an extra &log is fine: Making something &log by default
# shouldn't break users.
redef record Info$msg += { &log };

# Don't log extra1
redef record Info$extra1 -= { &log };

# Don't log extra2 (default, but remove &log) again
redef record Info$extra2 -= { &log };

# Do log extra3
redef record Info$extra3 += { &log };

# Redef extra4 from global scope (remove and re-add &log)
module GLOBAL;
redef record RedefRecordTest::Info$extra4 -= { &log };
redef record RedefRecordTest::Info$extra4 += { &log };

module RedefRecordTest;

# zeek_init() for testing of print and logging.
event zeek_init()
	{
        print "Info record_fields\n", record_fields(Info);
        local rec = Info(
		$ts=double_to_time(1660142487.54),
		$msg="msg",
		$extra1="extra1 value",
		$extra2="extra2 value",
		$extra3="extra3 value",
		$extra4="extra4 value"
	);
        print "Info record", rec;
        Log::create_stream(LOG, [$columns=Info, $path="test"]);
        Log::write(LOG, rec);
	}
