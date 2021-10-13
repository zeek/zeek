# @TEST-EXEC: zeek -b -r $TRACES/tls/dhe.pcap %INPUT
# @TEST-EXEC: cat ssl.log > ssl-all.log
# @TEST-EXEC: zeek -b -r $TRACES/tls/ecdhe.pcap %INPUT
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: zeek -b -r $TRACES/tls/ssl.v3.trace %INPUT
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: zeek -b -r $TRACES/tls/tls1_1.pcap %INPUT
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: zeek -b -r $TRACES/tls/dtls1_0.pcap %INPUT
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: zeek -b -r $TRACES/tls/dtls1_2.pcap %INPUT
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: zeek -b -r $TRACES/tls/tls13_wolfssl.pcap %INPUT
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: zeek -b -r $TRACES/tls/tls13draft23-chrome67.0.3368.0-canary.pcap %INPUT
# @TEST-EXEC: cat ssl.log >> ssl-all.log

# @TEST-EXEC: btest-diff ssl-all.log

# Test the new client and server key exchange events.

@load protocols/ssl/ssl-log-ext

