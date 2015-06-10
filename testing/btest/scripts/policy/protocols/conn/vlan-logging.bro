# A basic test of the vlan-logging script's logging modifications

# @TEST-EXEC: bro -r $TRACES/q-in-q.trace %INPUT
# @TEST-EXEC: btest-diff conn.log

@load protocols/conn/vlan-logging
