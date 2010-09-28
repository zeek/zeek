# $Id: brolite-sigs.bro 3856 2006-12-02 00:18:57Z vern $

# Bro Lite signature configuration file

# General policy - these scripts are more infrastructural than service
# oriented, so in general avoid changing anything here.
@load alarm	# open logging file for alarm events

# Set global constant.  This can be used in ifdef statements to determine 
# if signatures are enabled.
const use_signatures = T;

@load snort		# basic definitions for signatures
@load signatures	# the signature policy engine
@load sig-functions	# addl. functions added for signature accuracy
@load sig-action	# actions related to particular signatures

# Flag HTTP worm sources such as Code Red.
@load worm

# Do worm processing
redef notice_action_filters += { [RemoteWorm] = file_notice };

# Ports that need to be captured for signatures to see a useful
# cross section of traffic.
redef capture_filters += {
	["sig-http"] =
		"tcp port 80 or tcp port 8080 or tcp port 8000 or tcp port 8001",
	["sig-ftp"] = "port ftp",
	["sig-telnet"] = "port telnet",
	["sig-portmapper"] = "port 111",
	["sig-smtp"] = "port smtp",
	["sig-imap"] = "port 143",
	["sig-snmp"] = "port 161 or port 162",
	["sig-dns"] = "port 53",

	# rsh/rlogin/rexec
	["sig-rfoo"] = "port 512 or port 513 or port 515",

	# Range of TCP ports for general RPC traffic.  This can also
	# occur on other ports, but these should catch a lot without
	# a major performance hit.  We skip ports assosciated with
	# HTTP, SSH and M$.
	["sig-rpc"] = "tcp[2:2] > 32770 and tcp[2:2] < 32901 and tcp[0:2] != 80 and tcp[0:2] != 22 and tcp[0:2] != 139",
};

### Why is this called "tcp3"?
# Catch outbound M$ scanning.   Returns filter listing local addresses
# along with the interesting ports.
function create_tcp3_filter(): string
	{
	local local_addrs = "";
	local firsttime = T;

	for ( l in local_nets )
		{
		if ( firsttime )
			{
			local_addrs = fmt("src net %s", l);
			firsttime = F;
			}
		else
			local_addrs = fmt("%s or src net %s", local_addrs, l);
		}

	local MS_scan_ports =
		"dst port 135 or dst port 137 or dst port 139 or dst port 445";

	if ( local_addrs == "" )
		return MS_scan_ports;
	else
		return fmt("(%s) and (%s)", local_addrs, MS_scan_ports);
	}

# Create and apply the filter.
redef capture_filters += { ["tcp3"] = create_tcp3_filter()};

# Turn on ICMP analysis.
redef capture_filters += { ["icmp"] = "icmp"};

# Load the addendum signatures.  These are utility signatures that do not
# produce event messages.
redef signature_files += "sig-addendum";
