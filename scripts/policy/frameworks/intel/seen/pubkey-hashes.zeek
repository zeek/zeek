@load base/frameworks/intel
@load base/protocols/ssh
@load ./where-locations

event ssh_server_host_key(c: connection, hash: string)
	{
	local seen = Intel::Seen($indicator=hash,
				 $indicator_type=Intel::PUBKEY_HASH,
				 $conn=c,
				 $where=SSH::IN_SERVER_HOST_KEY);
	Intel::seen(seen);
	}
