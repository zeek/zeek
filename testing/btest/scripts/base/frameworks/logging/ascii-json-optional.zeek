# This test verifies the behavior of the JSON writer regarding unset optional
# values.  By default, such fields are skipped, while redef'ing
# LogAscii::json_include_unset_fields=T or using a filter's config table to set a
# field of the same name includes them with a null value.
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff testing.log
#
# @TEST-EXEC: zeek -b %INPUT LogAscii::json_include_unset_fields=T Testing::logname=testing_nullfields
# @TEST-EXEC: btest-diff testing_nullfields.log
#
# @TEST-EXEC: zeek -b %INPUT Testing::use_config_table=T Testing::logname=testing_nullfields_via_config
# @TEST-EXEC: btest-diff testing_nullfields_via_config.log

@load tuning/json-logs

module Testing;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log &optional;
        msg: string &log &optional;
    };

    global log_test: event(rec: Info);

    const logname = "testing" &redef;
    const use_config_table = F &redef;
}

event zeek_init() &priority=5
{
    Log::create_stream(LOG, [$columns=Info, $ev=log_test, $path=logname]);

    if ( use_config_table )
        {
        local f = Log::get_filter(LOG, "default");
        f$config = table(["json_include_unset_fields"] = "T");
        Log::add_filter(LOG, f);
        }

    local info: Info;
    info$msg = "Testing 1 2 3 ";
    Log::write(LOG, info);
}
