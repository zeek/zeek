@load conn-util
@load dce-rpc

redef capture_filters += {
	["dce-rpc"] = "tcp or udp",
};

global dce_rpc_tag: table[conn_id] of string &default = "";

const log_dce_rpc_tags = T &redef;
function get_dce_rpc_tag(id: conn_id): string
	{
	if ( id in dce_rpc_tag )
		return dce_rpc_tag[id];
	else
		return "";
	}

module DCE_RPC_tag;

global log = open_log_file("dce_rpc-tag") &redef;

function add_to_dce_rpc_tag(c: connection, name: string): bool
	{
	local id = c$id;
	local orig_tag = dce_rpc_tag[id];

	if ( orig_tag == "" )
		{
		dce_rpc_tag[id] = name;
		}
	else if ( strstr(orig_tag, name) == 0 )
		{
		dce_rpc_tag[id] = cat(orig_tag, ",", name);
		}

	return T;
	}

# Deficiency: it only looks at the bind request, but not the reply, so we
# do not know if the bind is successful.

event dce_rpc_bind(c: connection, uuid: string)
	{
	local if_name = DCE_RPC::dce_rpc_uuid_name[uuid];
	if ( log_dce_rpc_tags )
		print log, fmt("%.6f %s DCE_RPC_Bind: %s",
			network_time(), id_string(c$id), if_name);
	add_to_dce_rpc_tag(c, if_name);
	}

event delete_dce_rpc_tag(c: connection)
	{
	delete dce_rpc_tag[c$id];
	}

event connection_state_remove(c: connection)
	{
	if ( c$id in dce_rpc_tag )
		{
		if ( log_dce_rpc_tags )
			print log, fmt("conn %s start %.6f DCE/RPC [%s]",
				conn_id_string(c$id),
				c$start_time,
				dce_rpc_tag[c$id]);
		event delete_dce_rpc_tag(c);
		}
	}
