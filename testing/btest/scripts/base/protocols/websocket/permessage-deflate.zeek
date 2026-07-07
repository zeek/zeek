# @TEST-DOC: Test WebSocket permessage-deflate decompression.
# @TEST-EXEC: zeek -C -r $TRACES/websocket/websocket_compressed.pcap %INPUT > output.txt
# @TEST-EXEC: btest-diff output.txt
# @TEST-EXEC: btest-diff websocket.log

@load base/protocols/websocket

event websocket_frame_data(c: connection, is_orig: bool, data: string)
        {
        print fmt("websocket_frame_data: is_orig=%s len=%d", is_orig, |data|);
        }
