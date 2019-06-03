# This tests a successful login with pubkey using curve25519 as the KEX algorithm

# @TEST-EXEC: zeek -b -r $TRACES/ssh/ssh_kex_curve25519.pcap %INPUT
# @TEST-EXEC: btest-diff ssh.log

@load base/protocols/ssh