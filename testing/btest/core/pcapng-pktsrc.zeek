# @TEST-DOC: Tests the pcapng packet source, including sending events
#
# @TEST-EXEC: zeek -C -r $TRACES/pcapng-multi-interface.pcapng %INPUT > out
# @TEST-EXEC: btest-diff conn.log
