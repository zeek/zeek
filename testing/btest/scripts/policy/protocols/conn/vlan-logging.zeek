# A basic test of the vlan logging script

# @TEST-EXEC: zeek -r $TRACES/q-in-q.trace %INPUT
# @TEST-EXEC: btest-diff conn.log

@load protocols/conn/vlan-logging
