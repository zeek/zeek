##! Types, errors, and fields for analyzing DHCP data.  A helper file
##! for DHCP analysis scripts.

module DHCP;

export {

	## Types of DHCP messages. See :rfc:`1533`.
	const message_types = {
		[1]  = "DHCP_DISCOVER",
		[2]  = "DHCP_OFFER",
		[3]  = "DHCP_REQUEST",
		[4]  = "DHCP_DECLINE",
		[5]  = "DHCP_ACK",
		[6]  = "DHCP_NAK",
		[7]  = "DHCP_RELEASE",
		[8]  = "DHCP_INFORM",
		[9]  = "DHCP_FORCERENEW",
		[10] = "DHCP_LEASEQUERY",
		[11] = "DHCP_LEASEUNASSIGNED",
		[12] = "DHCP_DHCPLEASEUNKNOWN",
		[13] = "DHCP_LEASEACTIVE",
		[14] = "DHCP_BULKLEASEQUERY",
		[15] = "DHCP_LEASEQUERYDONE",
		[16] = "DHCP_ACTIVELEASEQUERY",
		[17] = "DHCP_LEASEQUERYSTATUS",
		[18] = "DHCP_TLS",
	} &default = function(n: count): string { return fmt("unknown-message-type-%d", n); };

}
