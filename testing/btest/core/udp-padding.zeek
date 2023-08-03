# Check that data contained in the UDP padding does not make it into protocol analysis

# @TEST-EXEC: zeek -r $TRACES/fake-syslog-with-padding.pcap %INPUT >out
# @TEST-EXEC: btest-diff syslog.log

