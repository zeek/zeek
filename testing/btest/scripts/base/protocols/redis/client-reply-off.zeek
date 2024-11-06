# @TEST-DOC: Test CLIENT REPLY OFF then ON again and a SKIP
#
# @TEST-EXEC: zeek -Cr $TRACES/redis/reply-off-on.trace base/protocols/redis %INPUT >output
# @TEST-EXEC: btest-diff redis.log
