# @TEST-DOC: Test Zeek parsing a trace file through the RESP analyzer.
#
# @TEST-EXEC: zeek -Cr $TRACES/redis/loop-redis.trace base/protocols/redis %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff resp.log

event RESP::data(c: connection, payload: RESP::RESPData)
    {
    print fmt("Testing RESP: %s", payload);
    }
