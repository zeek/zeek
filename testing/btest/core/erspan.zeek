# @TEST-EXEC: zeek -C -b -r $TRACES/erspan.trace %INPUT 
# @TEST-EXEC: btest-diff tunnel.log

@load base/frameworks/tunnels
