# Same as dump-events.zeek, but for JSON output.
# @TEST-REQUIRES: which jq
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
