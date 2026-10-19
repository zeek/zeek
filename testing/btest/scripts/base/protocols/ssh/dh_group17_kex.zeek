# @TEST-DOC: Verify the handling of diffie-hellman-group17-sha512
#
# @TEST-EXEC: zeek -b -r $TRACES/ssh/diffie-hellman-group17-sha512.pcap %INPUT
#
# @TEST-EXEC: btest-diff-cut -m ssh.log
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m uid name addl source weird.log

@load base/protocols/conn
@load base/protocols/ssh
@load base/frameworks/notice/weird
