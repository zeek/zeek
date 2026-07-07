# @TEST-DOC: Test WebSocket permessage-deflate decompression with complex Jupyter traffic.
# @TEST-EXEC: zeek -C -r $TRACES/websocket/jupyter-websocket.pcap %INPUT > output.txt
# @TEST-EXEC: btest-diff output.txt
# @TEST-EXEC: btest-diff websocket.log

@load base/protocols/websocket

event websocket_frame_data(c: connection, is_orig: bool, data: string)
        {
        print fmt("websocket_frame_data: is_orig=%s len=%d", is_orig, |data|);
        }
