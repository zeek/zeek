# @TEST-DOC: A Connection Request whose TPKT version is not 3 is a protocol violation, not an RDP connection.
#
# @TEST-EXEC: zeek -b -r $TRACES/rdp/rdp-tpkt-version.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m id.orig_p cookie rdp.log
# @TEST-EXEC: btest-diff-cut -m id.orig_p cause analyzer_name failure_reason analyzer_debug.log

@load base/protocols/rdp
@load frameworks/analyzer/debug-logging.zeek
