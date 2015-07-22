# A basic test of the known-hosts script's logging and asset_tracking options

# @TEST-EXEC: bro -r $TRACES/q-in-q.trace %INPUT
# @TEST-EXEC: btest-diff conn.log

@load protocols/conn/vlan-logging
