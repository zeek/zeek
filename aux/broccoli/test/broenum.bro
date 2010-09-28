# Depending on whether you want to use encryption or not,
# include "listen-clear" or "listen-ssl":
#
# @load listen-ssl
@load listen-clear

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

module enumtest;

type enumtype: enum { ENUM1, ENUM2, ENUM3, ENUM4 };

redef Remote::destinations += {
	["broenum"] = [$host = 127.0.0.1, $events = /enumtest/, $connect=F, $ssl=F]
};

event enumtest(e: enumtype)
	{
	print fmt("Received enum val %d/%s", e, e);
	}
