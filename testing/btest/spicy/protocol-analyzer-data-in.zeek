# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o test.hlto ssh.spicy ./ssh-cond.evt
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace test.hlto %INPUT
# @TEST-EXEC: btest-diff http.log

# @TEST-START-FILE ssh.spicy
module SSH;

import spicy;
import zeek;

type Context = tuple<data_chunks: uint64>;

public type Banner = unit {
    %context = Context;
    magic   : /SSH-/;
    version : /[^-]*/;
    dash    : /-/;
    software: /[^\r\n]*/;
};

on Banner::%done {
    zeek::protocol_begin("HTTP");

    zeek::protocol_data_in(True, b"GET /etc/passwd1 HTTP/1.0\r\n\r\n");
    zeek::protocol_data_in(False, b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");

    # We can get a handle to the existing HTTP analyzer.
    local http1 = zeek::protocol_handle_get_or_create("HTTP");
    zeek::protocol_data_in(True, b"GET /etc/passwd1.1 HTTP/1.0\r\n\r\n", http1);

    # We can get another handle to the existing HTTP analyzer.
    local http2 = zeek::protocol_handle_get_or_create("HTTP");
    zeek::protocol_data_in(False, b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n", http2);
    zeek::protocol_handle_close(http1);

    zeek::protocol_end();  # Noop.

    # Creating a DPD child analyzer creates no handle.
    zeek::protocol_begin(); # DPD
    zeek::protocol_data_in(True, b"GET /etc/passwd2 HTTP/1.0\r\n\r\n");
    zeek::protocol_data_in(False, b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
    zeek::protocol_end();
}
# @TEST-END-FILE

# @TEST-START-FILE ssh-cond.evt

import zeek;

protocol analyzer spicy::SSH over TCP:
    parse originator with SSH::Banner,
    port 22/tcp,
    replaces SSH;

# @TEST-END-FILE
