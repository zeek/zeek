# @TEST-EXEC: zeek -b -r $TRACES/rdp/rdp-proprietary-encryption.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/rdp

event rdp_client_cluster_data(c: connection, data: RDP::ClientClusterData)
	{
	print "RDP Client Cluster Data";
	print fmt("Flags: %08x",data$flags);
	print fmt("RedirSessionId: %08x",data$redir_session_id);
	print fmt("Redirection Supported: %08x",data$redir_supported);
	print fmt("ServerSessionRedirectionVersionMask: %08x",data$svr_session_redir_version_mask);
	print fmt("RedirectionSessionIDFieldValid: %08x",data$redir_sessionid_field_valid);
	print fmt("RedirectedSmartCard: %08x",data$redir_smartcard);
	}

event rdp_client_network_data(c: connection, channels: RDP::ClientChannelList)
	{
	print "RDP Client Channel List Options";
	for ( i in channels )
		print fmt("%08x", channels[i]$options);
	}
