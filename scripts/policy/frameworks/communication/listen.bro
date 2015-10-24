##! Loading this script will make the Bro instance listen for remote 
##! Bro instances to connect.

@load base/frameworks/communication
@load base/frameworks/broker

module Communication;

event bro_init() &priority=-10
	{
	Broker::listen(listen_port, fmt("%s", listen_interface));
	}
