@load base/frameworks/intel
@load ./where-locations

event connection_established(c: connection)
	{
	if ( c$orig$state == TCP_ESTABLISHED &&
	     c$resp$state == TCP_ESTABLISHED )
		{
		Intel::seen([$host=c$id$orig_h, $conn=c, $where=Conn::IN_ORIG]);
		Intel::seen([$host=c$id$resp_h, $conn=c, $where=Conn::IN_RESP]);
		}
	}
