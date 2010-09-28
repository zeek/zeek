# $Id: listen-clear.bro 416 2004-09-17 03:52:28Z vern $
#
# Listen for other Bros (non-SSL).

@load remote

# On which port to listen.
const listen_port_clear = Remote::default_port_clear &redef;

# On which IP to bind (0.0.0.0 for any interface)
const listen_if_clear = 0.0.0.0 &redef;

event bro_init()
	{
	listen(listen_if_clear, listen_port_clear, F);
	}
