# This tests a normal SSL connection and the log it outputs.

# @TEST-EXEC: zeek -b -r $TRACES/tls/dtls1_0.pcap %INPUT
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: btest-diff x509.log
# @TEST-EXEC: zeek -b -r $TRACES/tls/dtls1_2.pcap %INPUT
# @TEST-EXEC: cp ssl.log ssl1_2.log
# @TEST-EXEC: cp x509.log x5091_2.log
# @TEST-EXEC: btest-diff ssl1_2.log
# @TEST-EXEC: btest-diff x5091_2.log

@load base/protocols/ssl
