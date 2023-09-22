# @TEST-EXEC: zeek -b -r $TRACES/smtp.trace policy/misc/dump-events %INPUT >all-events.log
# @TEST-EXEC: zeek -b -r $TRACES/smtp.trace policy/misc/dump-events %INPUT DumpEvents::include_args=F >all-events-no-args.log
# @TEST-EXEC: zeek -b -r $TRACES/smtp.trace policy/misc/dump-events %INPUT DumpEvents::include=/smtp_/ >smtp-events.log
# @TEST-EXEC: zeek -b -r $TRACES/smtp.trace policy/misc/dump-events %INPUT DumpEvents::dump_all_events=T | grep -v "CPU: interval\|samples: load_sample_info\|path: string" > really-all-events.log
#
# @TEST-EXEC: btest-diff all-events.log
# @TEST-EXEC: btest-diff all-events-no-args.log
# @TEST-EXEC: btest-diff smtp-events.log
# @TEST-EXEC: btest-diff really-all-events.log

@load base/protocols/conn
@load base/protocols/smtp
