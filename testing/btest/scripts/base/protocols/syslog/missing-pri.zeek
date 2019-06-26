# @TEST-EXEC: zeek -r $TRACES/syslog-missing-pri.trace %INPUT
# @TEST-EXEC: btest-diff syslog.log

@load base/protocols/syslog
