# @TEST-EXEC: zeek -b -C -r $TRACES/ntp/ntpmode67.pcap %INPUT
# @TEST-EXEC: btest-diff ntp_control.log
# @TEST-EXEC: btest-diff ntp_private.log

@load base/protocols/ntp

