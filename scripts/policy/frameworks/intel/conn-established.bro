@load base/frameworks/intel

export {
	redef enum Intel::Where += {
		Conn::IN_ORIG,
		Conn::IN_RESP,
	};
}

event connection_established(c: connection)
	{
	Intel::seen([$host=c$id$orig_h, $conn=c, $where=Conn::IN_ORIG]);
	Intel::seen([$host=c$id$resp_h, $conn=c, $where=Conn::IN_RESP]);
	}
