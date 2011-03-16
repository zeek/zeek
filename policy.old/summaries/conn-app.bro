@load conn-app-reduced

@load ftp
@load dce-rpc

event new_connection(c: connection)
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] in DCE_RPC::dce_rpc_endpoint )
		{
		# local uuid = DCE_RPC::dce_rpc_endpoint[id$resp_h, id$resp_p];
		# conn_app[id] = fmt("dce-rpc-%s",
		#	 ( uuid in DCE_RPC::dce_rpc_uuid_name ) ?
		#	 DCE_RPC::dce_rpc_uuid_name[uuid] : "unknown");
		conn_app[id] = "dce-rpc";
		}
	else if ( FTP::is_ftp_data_connection(c) )
		{
		conn_app[id] = "ftp-data";
		}
	}
