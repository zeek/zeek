# @TEST-EXEC: zeek -b -r $TRACES/syslog-missing-pri.pcap %INPUT
# @TEST-EXEC: btest-diff syslog.log

@load base/protocols/syslog
