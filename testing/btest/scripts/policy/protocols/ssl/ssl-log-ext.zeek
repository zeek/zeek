# Does not work in spicy version, due to missing DTLS support
# @TEST-REQUIRES: ! have-spicy-ssl

# @TEST-EXEC: zeek -b -r $TRACES/tls/dhe.pcap %INPUT
# @TEST-EXEC: echo "#file dhe.pcap" > ssl-all.log
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: zeek -b -r $TRACES/tls/ecdhe.pcap %INPUT
# @TEST-EXEC: echo "#file ecdhe.pcap" >> ssl-all.log
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: zeek -b -r $TRACES/tls/ssl.v3.pcap %INPUT
# @TEST-EXEC: echo "#file ssl.v3.pcap" >> ssl-all.log
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: zeek -b -r $TRACES/tls/tls1_1.pcap %INPUT
# @TEST-EXEC: echo "#file tls1_1.pcap" >> ssl-all.log
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: zeek -b -r $TRACES/tls/dtls1_0.pcap %INPUT
# @TEST-EXEC: echo "#file dtls1_0.pcap" >> ssl-all.log
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: zeek -b -r $TRACES/tls/dtls1_2.pcap %INPUT
# @TEST-EXEC: echo "#file dtls1_2.pcap" >> ssl-all.log
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: zeek -b -r $TRACES/tls/tls13_wolfssl.pcap %INPUT
# @TEST-EXEC: echo "#file tls13_wolfssl.pcap" >> ssl-all.log
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: zeek -b -r $TRACES/tls/tls13draft23-chrome67.0.3368.0-canary.pcap %INPUT
# @TEST-EXEC: echo "#file tls13draft23-chrome67.0.3368.0-canary.pcap" >> ssl-all.log
# @TEST-EXEC: cat ssl.log >> ssl-all.log
# @TEST-EXEC: zeek -b -r $TRACES/tls/tls13-ech.pcap %INPUT
# @TEST-EXEC: echo "#file tls13-ech.pcap" >> ssl-all.log
# @TEST-EXEC: cat ssl.log >> ssl-all.log

# @TEST-EXEC: btest-diff ssl-all.log

# Test the new client and server key exchange events.

@load protocols/ssl/ssl-log-ext
