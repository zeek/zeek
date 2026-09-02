# @TEST-DOC: Tests the limitations on the size of X509 and OCSP parsing
#
# @TEST-EXEC: zeek -r $TRACES/tls/ocsp-http-get.pcap %INPUT
# @TEST-EXEC: cat weird.log | zeek-cut -m >> combined-weird.log
# @TEST-EXEC: rm weird.log
# @TEST-EXEC: zeek -r $TRACES/tls/google-duplicate.trace %INPUT
# @TEST-EXEC: cat weird.log | zeek-cut -m >> combined-weird.log
# @TEST-EXEC: btest-diff combined-weird.log

redef OCSP::max_bytes = 10;
redef X509::max_bytes = 10;
