# @TEST-DOC: Regression for not being able to use ssl_extension_pre_shared_key_client_hello or ssl_extension_pre_shared_key_server_hello in isolation.
#
# @TEST-EXEC: zeek -b -r $TRACES/tls/tls-13draft19-early-data.pcap psk_client.zeek > client.out
# @TEST-EXEC: zeek -b -r $TRACES/tls/tls-13draft19-early-data.pcap psk_server.zeek > server.out
# @TEST-EXEC: zeek -b -r $TRACES/tls/tls-13draft19-early-data.pcap psk_client.zeek psk_server.zeek > both.out

# @TEST-EXEC: btest-diff client.out
# @TEST-EXEC: btest-diff server.out
# @TEST-EXEC: btest-diff both.out

# @TEST-START-FILE psk_client.zeek
@load base/protocols/ssl

event ssl_extension_pre_shared_key_client_hello(c: connection, is_client: bool, identities: psk_identity_vec, binders: string_vec)
        {
        print "pre_shared_key client hello", identities;
        }
# @TEST-END-FILE psk_client.zeek

# @TEST-START-FILE psk_server.zeek
@load base/protocols/ssl

event ssl_extension_pre_shared_key_server_hello(c: connection, is_client: bool, selected_identity: count)
        {
        print "pre_shared_key server hello", selected_identity;
        }
# @TEST-END-FILE
