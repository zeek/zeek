##! WebSocket constants.

module WebSocket;

export {
	const OPCODE_CONTINUATION = 0x00;
	const OPCODE_TEXT         = 0x01;
	const OPCODE_BINARY       = 0x02;
	const OPCODE_CLOSE        = 0x08;
	const OPCODE_PING         = 0x09;
	const OPCODE_PONG         = 0x0a;

	const opcodes: table[count] of string = {
		[OPCODE_CONTINUATION] = "continuation",
		[OPCODE_TEXT]         = "text",
		[OPCODE_BINARY]       = "binary",
		[OPCODE_CLOSE]        = "close",
		[OPCODE_PING]         = "ping",
		[OPCODE_PONG]         = "pong",
	} &default=function(opcode: count): string { return fmt("unknown-%x", opcode); } &redef;

	const HANDSHAKE_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
}
