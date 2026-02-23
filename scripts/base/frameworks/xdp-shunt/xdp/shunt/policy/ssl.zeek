##! Shunts SSL traffic after connection established.

@load xdp

event ssl_established(c: connection)
	{
	XDP::Shunt::ConnID::shunt(XDP::conn_id_to_canonical(c$id));
	}

