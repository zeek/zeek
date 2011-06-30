# $Id: listen-ssl.bro 1015 2005-01-31 13:46:50Z kreibich $
#
# Listen for other Bros (SSL).

@load remote

# On which port to listen.
const listen_port_ssl = Remote::default_port_ssl &redef;

# On which IP to bind (0.0.0.0 for any interface)
const listen_if_ssl = 0.0.0.0 &redef;

event bro_init()
	{
	listen(listen_if_ssl, listen_port_ssl, T);
	}
