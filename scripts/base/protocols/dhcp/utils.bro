##! Utilities specific for DHCP processing.

module DHCP;

export {
	## Reverse the octets of an IPv4 IP.
	##
	## ip: An :bro:type:`addr` IPv4 address.
	##
	## Returns: A reversed addr.
	global reverse_ip: function(ip: addr): addr;
}

function reverse_ip(ip: addr): addr
	{
	local octets = split(cat(ip), /\./);
	return to_addr(cat(octets[4], ".", octets[3], ".", octets[2], ".", octets[1]));
	}

