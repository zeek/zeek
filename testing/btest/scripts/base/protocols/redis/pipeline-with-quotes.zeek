# @TEST-DOC: Test Zeek parsing "pipelined" data responses
#
# @TEST-EXEC: zeek -Cr $TRACES/redis/pipeline-quotes.trace base/protocols/redis %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff resp.log
# @TEST-EXEC: btest-diff weird.log

# Tests unserialized data where quotes should make one token
