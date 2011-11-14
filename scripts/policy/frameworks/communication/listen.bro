##! Loading this script will make the Bro instance listen for remote 
##! Bro instances to connect.

@load base/frameworks/communication

module Communication;

event bro_init() &priority=-10
	{
	enable_communication();
	listen(listen_interface, listen_port, listen_ssl);
	}
