# Test that certificate log caching works as expected.
# The trace has duplicate certificates - they should only be output once to X509.log.

# @TEST-EXEC: zeek -b -r $TRACES/tls/google-duplicate.trace %INPUT
# @TEST-EXEC: btest-diff x509.log

@load base/protocols/ssl
