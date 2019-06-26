# @TEST-EXEC: zeek -C -r $TRACES/tls/missing-intermediate.pcap $SCRIPTS/external-ca-list.zeek %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-x509-names | $SCRIPTS/diff-remove-timestamps" btest-diff ssl.log

@load protocols/ssl/validate-certs

redef SSL::ssl_cache_intermediate_ca = F;
