# @TEST-EXEC: zeek -b -Cr $TRACES/ssh/reverse-ssh.pcap %INPUT
# @TEST-EXEC: btest-diff ssh.log
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/conn
@load base/protocols/ssh
