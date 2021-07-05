# @TEST-EXEC: zeek -b -r $TRACES/tls/ecdhe.pcap %INPUT
# @TEST-EXEC: btest-diff x509.log

@load protocols/ssl/log-certs-base64

