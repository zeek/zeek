# This tests a successful login with pubkey using ML-KEM as the KEX algorithm

# @TEST-EXEC: zeek -b -r $TRACES/ssh/ssh_kex_mlkem.pcap %INPUT
# @TEST-EXEC: btest-diff ssh.log

@load base/protocols/ssh
