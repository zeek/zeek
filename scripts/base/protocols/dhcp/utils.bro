##! Utilities specific for DHCP processing.

module DHCP;

export {
	## Reverse the octets of an IPv4 address.
	##
	## ip: An IPv4 address.
	##
	## Returns: A reversed IPv4 address.
	global reverse_ip: function(ip: addr): addr;
}

function reverse_ip(ip: addr): addr
	{
	local octets = split(cat(ip), /\./);
	return to_addr(cat(octets[4], ".", octets[3], ".", octets[2], ".", octets[1]));
	}

