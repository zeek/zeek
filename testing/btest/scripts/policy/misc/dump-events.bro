# @TEST-EXEC: bro -r $TRACES/smtp.trace policy/misc/dump-events.bro >all-events.log
# @TEST-EXEC: bro -r $TRACES/smtp.trace policy/misc/dump-events.bro DumpEvents::include_args=F >all-events-no-args.log
# @TEST-EXEC: bro -r $TRACES/smtp.trace policy/misc/dump-events.bro DumpEvents::include=/smtp_/ >smtp-events.log
# 
# @TEST-EXEC: btest-diff all-events.log
# @TEST-EXEC: btest-diff all-events-no-args.log
# @TEST-EXEC: btest-diff smtp-events.log
