# @TEST-DOC: Check which NTP records are logged when messages change modes on a flow.
#
# @TEST-EXEC: zeek -b -r $TRACES/ntp/mixed-mode-logging.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m id.orig_p mode ntp.log
# @TEST-EXEC: btest-diff-cut -m id.orig_p mode ntp_control.log
# @TEST-EXEC: btest-diff-cut -m id.orig_p mode ntp_private.log

@load base/protocols/ntp
