module DHCPv6;

export {
	const message_types = {
		[1]  = "SOLICIT",
	} &default = function(n: count): string { return fmt("unknown-message-type-%d", n); };

	## Option types mapped to their names.
	const option_types = {
		[1] = "???",
	} &default = function(n: count): string { return fmt("unknown-option-type-%d", n); };
}
