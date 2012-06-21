module SOCKS;

export {
	type RequestType: enum {
		CONNECTION    = 1,
		PORT          = 2,
		UDP_ASSOCIATE = 3,
	};

	const v5_authentication_methods: table[count] of string = {
		[0] = "No Authentication Required",
		[1] = "GSSAPI",
		[2] = "Username/Password",
		[3] = "Challenge-Handshake Authentication Protocol",
		[5] = "Challenge-Response Authentication Method",
		[6] = "Secure Sockets Layer",
		[7] = "NDS Authentication",
		[8] = "Multi-Authentication Framework",
		[255] = "No Acceptable Methods",
	} &default=function(i: count):string { return fmt("unknown-%d", i); };

	const v4_status: table[count] of string = {
		[0x5a] = "succeeded",
		[0x5b] = "general SOCKS server failure",
		[0x5c] = "request failed because client is not running identd",
		[0x5d] = "request failed because client's identd could not confirm the user ID string in the request",
	} &default=function(i: count):string { return fmt("unknown-%d", i); };

	const v5_status: table[count] of string = {
		[0] = "succeeded",
		[1] = "general SOCKS server failure",
		[2] = "connection not allowed by ruleset",
		[3] = "Network unreachable",
		[4] = "Host unreachable",
		[5] = "Connection refused",
		[6] = "TTL expired",
		[7] = "Command not supported",
		[8] = "Address type not supported",
	} &default=function(i: count):string { return fmt("unknown-%d", i); };
}
