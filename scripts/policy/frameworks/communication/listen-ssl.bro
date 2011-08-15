##! Listen for other Bro instances and encrypt the connection with SSL.

@load base/frameworks/communication

module Communication;

export {
	## Which port to listen on for SSL encrypted connections.
	const listen_port_ssl = Communication::default_port_ssl &redef;
	
	## Which IP address to bind to for SSL encrypted connections
	## (0.0.0.0 for any interface).
	const listen_if_ssl = 0.0.0.0 &redef;
	
}

event bro_init() &priority=-10
	{
	enable_communication();
	listen(listen_if_ssl, listen_port_ssl, T);
	}
