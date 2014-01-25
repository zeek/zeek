# @TEST-EXEC: bro -r $TRACES/ssl.v3.trace policy/misc/dump-events.bro >all-events.log
# @TEST-EXEC: bro -r $TRACES/ssl.v3.trace policy/misc/dump-events.bro DumpEvents::include_args=F >all-events-no-args.log
# @TEST-EXEC: bro -r $TRACES/ssl.v3.trace policy/misc/dump-events.bro DumpEvents::include=/ssl_/ >ssl-events.log
# 
# @TEST-EXEC: btest-diff all-events.log
# @TEST-EXEC: btest-diff all-events-no-args.log
# @TEST-EXEC: btest-diff ssl-events.log
