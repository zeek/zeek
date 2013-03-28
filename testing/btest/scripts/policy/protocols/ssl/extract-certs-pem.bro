# @TEST-EXEC: bro -r $TRACES/ssl.v3.trace %INPUT 
# @TEST-EXEC: btest-diff certs-remote.pem

@load protocols/ssl/extract-certs-pem

redef SSL::extract_certs_pem = ALL_HOSTS;
