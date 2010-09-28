# Depending on whether you want to use encryption or not,
# include "listen-clear" or "listen-ssl":
#
# @load listen-ssl
@load listen-clear
@load conn
@load dpd

# Let's make sure we use the same port no matter whether we use encryption or not:
#
@ifdef (listen_port_clear)
redef listen_port_clear    = 47758/tcp;
@endif

# If we're using encrypted communication, redef the SSL port and hook in
# the necessary certificates:
#
@ifdef (listen_port_ssl)
redef listen_port_ssl      = 47758/tcp;
redef ssl_ca_certificate   = "<path>/ca_cert.pem";
redef ssl_private_key      = "<path>/bro.pem";
@endif

redef Remote::destinations += {
	["broconn"] = [$host = 127.0.0.1, $connect=F, $ssl=F]
};

redef dpd_conn_logs = T;

function services_to_string(ss: string_set): string
{
	local result = "";

	for (s in ss)
	    result = fmt("%s %s", result, s);
	
	return result;
}

event new_connection(c: connection)
{
	print fmt("new_connection: %s, services:%s",
	          id_string(c$id), services_to_string(c$service));
}

event connection_finished(c: connection)
{
	print fmt("connection_finished: %s, services:%s",
	          id_string(c$id), services_to_string(c$service));
}
