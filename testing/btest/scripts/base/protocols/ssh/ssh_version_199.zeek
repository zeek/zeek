# This tests a successful auth between an SSHv1.99 and SSHv2.

# @TEST-EXEC: zeek -r $TRACES/ssh/ssh_version_199.pcap %INPUT
# @TEST-EXEC: btest-diff ssh.log

@load base/protocols/ssh
