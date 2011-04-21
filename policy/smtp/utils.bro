
module SMTP;

function find_address_in_smtp_header(header: string): string
{
	local ips = find_ip_addresses(header);
	# If there are more than one IP address found, return the second.
	if ( |ips| > 1 )
		return ips[2];
	# Otherwise, return the first.
	else if ( |ips| > 0 )
		return ips[1];
	# Otherwise, there wasn't an IP address found.
	else
		return "";
}
