# @TEST-EXEC: zeek -b -Cr $TRACES/ssh/sshguess.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/ssh

event ssh2_dh_gex_init(c: connection, is_orig: bool) {
    print("Found SSH2_DH_GEX_INIT event");
}
