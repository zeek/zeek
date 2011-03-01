# $Id: ssh.bro 6588 2009-02-17 00:02:53Z vern $

module SSH;

export {
	# If true, we tell the event engine to not look at further data
	# packets after the initial SSH handshake. Helps with performance
	# (especially with large file transfers) but precludes some
	# kinds of analyses (e.g., tracking connection size).
	const skip_processing_after_handshake = T &redef;

	global ssh_ports = { 22/tcp } &redef;
}

redef capture_filters += { ["ssh"] = "tcp port 22" };

redef dpd_config += { [ANALYZER_SSH] = [$ports = ssh_ports] };

const ssh_log = open_log_file("ssh") &redef;

# Indexed by address and T for client, F for server.
global did_ssh_version: table[addr, bool] of count
				&default = 0 &read_expire = 7 days;

event ssh_client_version(c: connection, version: string)
	{
	if ( ++did_ssh_version[c$id$orig_h, T] == 1 )
		print ssh_log, fmt("%s %s \"%s\"", c$id$orig_h, "C", version);

	if ( skip_processing_after_handshake )
		{
		skip_further_processing(c$id);
		set_record_packets(c$id, F);
		}
	}

event ssh_server_version(c: connection, version: string)
	{
	if ( ++did_ssh_version[c$id$resp_h, F] == 1 )
		print ssh_log, fmt("%s %s \"%s\"", c$id$resp_h, "S", version);
	}
