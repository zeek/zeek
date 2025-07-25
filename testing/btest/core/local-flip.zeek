# @TEST-DOC: This check that local origin/responders are correctly flipped when the flip occurs later in the connection.
# @TEST-EXEC: zeek -b -C -r $TRACES/http/zeek-image-post-1080-8000-x.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log

@load base/protocols/http
@load policy/protocols/conn/mac-logging
