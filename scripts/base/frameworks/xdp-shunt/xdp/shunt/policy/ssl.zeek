##! Shunts SSL traffic after connection established.

@load xdp

event ssl_established(c: connection)
	{
	XDP::Shunt::ConnID::shunt(c$id);
	}

