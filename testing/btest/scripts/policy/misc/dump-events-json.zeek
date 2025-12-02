# Same as dump-events.zeek, but for JSON output.
# @TEST-REQUIRES: which jq
#
# jq pre version 1.7 rendered 0.0 as 0. Skip this test on systems with
# such old jq version. jq 1.7 is fixed, released September 2023.
# https://github.com/jqlang/jq/issues/1301#issuecomment-2035877468
# @TEST-REQUIRES: test "$(echo 0.0 | jq)" = "0.0"
#
# @TEST-EXEC: zeek -b -r $TRACES/smtp.trace policy/misc/dump-events %INPUT | jq >all-events.json
# @TEST-EXEC: zeek -b -r $TRACES/smtp.trace policy/misc/dump-events %INPUT DumpEvents::include_args=F | jq >all-events-no-args.json
# @TEST-EXEC: zeek -b -r $TRACES/smtp.trace policy/misc/dump-events %INPUT DumpEvents::include=/smtp_/ | jq >smtp-events.json
#
# In the following, the Pcap::file_done event contains the full path to the
# processed pcap, so we normalize it out:
# @TEST-EXEC: zeek -b -r $TRACES/smtp.trace policy/misc/dump-events %INPUT DumpEvents::dump_all_events=T | jq 'select(.event == "Pcap::file_done").args.path = "XXX"' >really-all-events.json
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff all-events.json
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff all-events-no-args.json
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff smtp-events.json
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff really-all-events.json

@load base/protocols/conn
@load base/protocols/smtp

redef DumpEvents::use_json = T;
