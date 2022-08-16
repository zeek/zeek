##! This script can be used to add back the fields ``tx_hosts``, ``rx_hosts``
##! and ``conn_uids`` to the :zeek:see:`Files::Info` record and thereby also
##! back into the ``files.log``. These fields have been removed in Zeek 5.1
##! and replaced with the more commonly used ``uid`` and ``id`` fields.
##!
##! It's only purpose is to provide an easy way to add back the fields such that
##! existing downstream processes continue to work without the need to adapt them.
##! This script will be removed with Zeek 6.1 at which point downstream processes
##! hopefully have switched over to use ``uid`` and ``id`` instead.

# Remove in v6.1.

@load base/frameworks/files

module Files;

# Add back the fields to Files::Info.
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

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=9
	{
	local cid = c$id;
	add f$info$conn_uids[c$uid];
	add f$info$tx_hosts[f$is_orig ? cid$orig_h : cid$resp_h];
	add f$info$rx_hosts[f$is_orig ? cid$resp_h : cid$orig_h];
	}

# For every log write to files.log, ensure tx_hosts, rx_hosts and conn_uids
# hold just a single value. Use a high priority for this handler to ensure
# this happens before any user defined hooks.
hook Log::log_stream_policy(rec: any, id: Log::ID) &priority=100
	{
	if ( id != Files::LOG )
		return;

	local info = rec as Files::Info;

	# In the common case of a single connection (or the less common case
	# of no connection), there's nothing to do in this hook.
	if ( |info$conn_uids| == 1 || ! info?$id )
		return;

	# Make singular tx_hosts, rx_hosts and conn_uids fields based on
	# the active uid. Note, this currently assumes that Files::Info$is_orig
	# is the same for all connections. This seems reasonable given that
	# all connections will use the same protocol.
	local cid = info$id;
	info$conn_uids = set(info$uid);
	info$tx_hosts = set(info$is_orig ? cid$orig_h : cid$resp_h);
	info$rx_hosts = set(info$is_orig ? cid$resp_h : cid$orig_h);
	}
