# @TEST-EXEC: zeek -C -r $TRACES/globus-url-copy-bad-encoding.trace %INPUT
# @TEST-EXEC: btest-diff weird.log
