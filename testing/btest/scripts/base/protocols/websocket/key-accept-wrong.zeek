# @TEST-DOC: Test weird generation when the Sec-WebSocket-Accept socket isn't as expected.
#
# @TEST-EXEC: zeek -b -r $TRACES/websocket/wrong-accept-header.pcap %INPUT
# @TEST-EXEC: btest-diff websocket.log
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/websocket
