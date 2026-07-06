event websocket_frame_data(c: connection, is_orig: bool, data: string)
    {
    print fmt("Direction: %s | Payload: %s", is_orig ? "Client->Server" : "Server->Client", data);
    }
