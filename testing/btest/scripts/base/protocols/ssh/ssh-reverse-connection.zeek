# @TEST-EXEC: zeek -b -Cr $TRACES/ssh/reverse-ssh.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/ssh

event ssh2_ecc_init(c: connection, is_orig: bool) {
    ## If a machine sends out the initial key material for the handshake, this should come from the client.
    ## In most cases, this client is the machine that set up the TCP connection. 
    if ( ! is_orig ) {
        print("Detected an ECC INIT not from the TCP client");
    }
}
