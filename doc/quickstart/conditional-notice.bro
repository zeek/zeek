@load protocols/ssl/expiring-certs

const watched_servers: set[addr] = {
	87.98.220.10,
} &redef;

# Site::local_nets usually isn't something you need to modify if
# BroControl automatically sets it up from networks.cfg.  It's
# shown here for completeness.
redef Site::local_nets += {
	87.98.0.0/16,
};

hook Notice::policy(n: Notice::Info)
	{
	if ( n$note != SSL::Certificate_Expired )
		return;

	if ( n$id$resp_h !in watched_servers )
		return;

	add n$actions[Notice::ACTION_EMAIL];
	}

