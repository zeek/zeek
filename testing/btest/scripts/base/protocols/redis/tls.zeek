# @TEST-DOC: Test Zeek with RESP over TLS so it doesn't get gibberish
#
# @TEST-EXEC: zeek -Cr $TRACES/redis/tls.trace base/protocols/redis %INPUT >output
# @TEST-EXEC-FAIL: test -f resp.log

# The logs should probably be empty since it's all encrypted
