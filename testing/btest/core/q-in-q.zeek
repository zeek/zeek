# @TEST-EXEC: zeek -b -r $TRACES/q-in-q.trace base/protocols/conn
# @TEST-EXEC: btest-diff conn.log
