# @TEST-DOC: Verify SSH with version strings that do not follow RFC 4253.
#
# @TEST-EXEC: zeek -b -r $TRACES/ssh/rssh.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log

@load base/protocols/conn
@load base/protocols/ssh
