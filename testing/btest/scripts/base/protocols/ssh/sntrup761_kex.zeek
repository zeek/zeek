# @TEST-DOC: Verify the handling of sntrup761x25519-sha512
#
# @TEST-EXEC: zeek -b -r $TRACES/ssh/sntrup761x25519-sha512.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m ssh.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
#
# @TEST-EXEC: test ! -f weird.log
# @TEST-EXEC: test ! -f analyzer.log

@load base/protocols/conn
@load base/protocols/ssh
@load base/frameworks/notice/weird
