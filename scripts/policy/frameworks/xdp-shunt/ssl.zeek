##! Shunts SSL traffic after connection established.

@ifdef ( XDP::__load_and_attach )

@load ./main
@load ./shunt_conn_id

event ssl_established(c: connection)
	{
	XDP::Shunt::ConnID::shunt(c);
	}
@endif
