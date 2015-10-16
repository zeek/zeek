# @TEST-EXEC: bro -C -r $TRACES/tls/missing-intermediate.pcap $SCRIPTS/external-ca-list.bro %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER="$SCRIPTS/diff-remove-x509-names | $SCRIPTS/diff-remove-timestamps" btest-diff ssl.log

@load protocols/ssl/validate-certs.bro

redef SSL::ssl_cache_intermediate_ca = F;
