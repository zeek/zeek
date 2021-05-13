# Test that checks that files.log is generated if the respective option is set.

# @TEST-EXEC: zeek -b -r $TRACES/tls/google-duplicate.trace %INPUT
# @TEST-EXEC: btest-diff files.log

@load base/protocols/ssl

redef X509::log_x509_in_files_log = T;
