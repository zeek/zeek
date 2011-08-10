##! Listen for other Bro instances to make unencrypted connections.

@load base/frameworks/communication/main

module Communication;

export {
	## Which port to listen on for clear connections.
	const listen_port_clear = Communication::default_port_clear &redef;
	
	## Which IP address to bind to (0.0.0.0 for any interface).
	const listen_if_clear = 0.0.0.0 &redef;
	
}

event bro_init() &priority=-10
	{
	enable_communication();
	listen(listen_if_clear, listen_port_clear, F);
	}
