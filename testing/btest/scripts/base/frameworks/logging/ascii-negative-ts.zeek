# @TEST-DOC: Test timestamp representations of a negative value in JSON.
#
# @TEST-EXEC: zeek -b %INPUT LogAscii::json_timestamps=JSON::TS_EPOCH;
# @TEST-EXEC: mv test.log test.log.ts_epoch
# @TEST-EXEC: zeek -b %INPUT LogAscii::json_timestamps=JSON::TS_MILLIS;
# @TEST-EXEC: mv test.log test.log.ts_millis
# @TEST-EXEC: zeek -b %INPUT LogAscii::json_timestamps=JSON::TS_MILLIS_UNSIGNED;
# @TEST-EXEC: mv test.log test.log.ts_millis_unsigned
# @TEST-EXEC: zeek -b %INPUT LogAscii::json_timestamps=JSON::TS_ISO8601
# @TEST-EXEC: mv test.log test.log.ts_iso8601
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff test.log.ts_epoch
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff test.log.ts_millis
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff test.log.ts_millis_unsigned
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff test.log.ts_iso8601

module TEST;

export {
    redef enum Log::ID += { LOG };
    type Test: record {
        ts: time &log;
    };
}

redef LogAscii::use_json=T;

event zeek_init() {
    Log::create_stream(TEST::LOG, [$columns=TEST::Test, $path="test"]);
    Log::write(TEST::LOG, [$ts=double_to_time(-315619200)]);
}
