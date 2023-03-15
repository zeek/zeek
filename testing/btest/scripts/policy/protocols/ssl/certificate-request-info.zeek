# @TEST-EXEC: zeek -C -r $TRACES/tls/certificate-request-failed.pcap %INPUT
# @TEST-EXEC: btest-diff ssl.log

@load protocols/ssl/certificate-request-info
