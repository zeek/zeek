import asyncio
import websockets
import sys

async def handler(websocket):
    # Receive the client's message
    msg = await websocket.recv()
    print(f"[Server] Received message of length {len(msg)}")
    
    # Send a highly compressible response back to the client
    response_msg = "Zeek_WebSocket_Test_String_" * 50
    await websocket.send(response_msg)
    print(f"[Server] Sent response of length {len(response_msg)}")

async def main(use_compression):
    # In the websockets library, "deflate" enables permessage-deflate.
    # Setting it to None explicitly disables it.
    compression_setting = "deflate" if use_compression else None
    
    # 1. Start the server in the background
    server = await websockets.serve(
        handler, "127.0.0.1", 8765, compression=compression_setting
    )
    
    # 2. Connect the client to the server
    uri = "ws://127.0.0.1:8765"
    async with websockets.connect(uri, compression=compression_setting) as websocket:
        # Send a highly compressible payload
        client_msg = "Hello_Zeek_Analyzer_" * 50
        await websocket.send(client_msg)
        print(f"[Client] Sent message of length {len(client_msg)}")
        
        # Await the server's response
        resp = await websocket.recv()
        print(f"[Client] Received message of length {len(resp)}")

    # 3. Clean up and shut down the server
    server.close()
    await server.wait_closed()

if __name__ == "__main__":
    # Simple CLI toggle for compression
    use_comp = True
    if len(sys.argv) > 1 and sys.argv[1] == "--no-comp":
        use_comp = False
        print("--- Running baseline WITHOUT compression ---")
    else:
        print("--- Running WITH permessage-deflate compression ---")
        
    asyncio.run(main(use_comp))
