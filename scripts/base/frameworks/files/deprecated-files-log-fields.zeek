@deprecated Remove in v6.1. tx_hosts, rx_hosts and conn_uids will be removed.

# Trickery to conditionally add the multi-connection related fields to
# the File::Info record for opt-in backwards compatibility.
#
# If this is too hacky, an alternative would be to exclude the fields via
# the default log filter as done in protocols/ssl/files.zeek, but that
# doesn't work for Zeek setups that do not use a default filter at all.
# (*cough*Seth*cough*). We also would like to sunset tx_hosts, rx_hosts,
# etc. It wouldn't allow us to cut out the rx_hosts, tx_hosts, conn_uids
# fields either.
redef record Info += {
	## If this file was transferred over a network
	## connection this should show the host or hosts that
	## the data sourced from.
	tx_hosts: set[addr] &default=addr_set() &log;

	## If this file was transferred over a network
	## connection this should show the host or hosts that
	## the data traveled to.
	rx_hosts: set[addr] &default=addr_set() &log;

	## Connection UIDs over which the file was transferred.
	conn_uids: set[string] &default=string_set() &log;
};

# Update sets at file_over_new_connection time for potential script users.
event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=9
	{
	local cid = c$id;
	add f$info$conn_uids[c$uid];
	add f$info$tx_hosts[f$is_orig ? cid$orig_h : cid$resp_h];
	add f$info$rx_hosts[f$is_orig ? cid$resp_h : cid$orig_h];
	}
