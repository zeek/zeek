#@TEST-DOC: Test that analyzer ID set for spicy protocol analyzers
#@TEST-EXEC: zeek -r $TRACES/postgresql/psql-aws-ssl-preferred.pcap %INPUT > out
#@TEST-EXEC: btest-diff out

event PostgreSQL::ssl_request(c: connection) {
        print c$uid, "PostgreSQL::ssl_request", current_analyzer();
}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) {
        print c$uid, "ssl_client_hello", current_analyzer();
}
