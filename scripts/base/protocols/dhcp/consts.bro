##! Types, errors, and fields for analyzing DHCP data.  A helper file
##! for DHCP analysis scripts.

module DHCP;

export {

	## Types of DHCP messages. See :rfc:`1533`.
	const message_types = {
		[1] = "DHCP_DISCOVER",
		[2] = "DHCP_OFFER",
		[3] = "DHCP_REQUEST",
		[4] = "DHCP_DECLINE",
		[5] = "DHCP_ACK",
		[6] = "DHCP_NAK",
		[7] = "DHCP_RELEASE",
		[8] = "DHCP_INFORM",
	} &default = function(n: count): string { return fmt("unknown-message-type-%d", n); };

}
