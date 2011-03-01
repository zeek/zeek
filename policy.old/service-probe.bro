# $Id: service-probe.bro 5892 2008-07-01 02:37:03Z vern $
#
# Detects hosts that continually bang away at a particular service
# of a local host, for example for brute-forcing passwords.
#
# Written by Jim Mellander, LBNL.
# Updated by Robin Sommer, ICSI.

@load conn

module ServiceProbe;

export {
	redef enum Notice += { ServiceProbe };

	# No work gets done unless this is set.
	global detect_probes = F &redef;

	# By default, look for service probes targeting MySQL and SSH.
	global probe_ports = { 1433/tcp, 22/tcp, } &redef;

	# They have to connect to this many to be flagged.
	global connect_threshold: table[port] of count &default=100 &redef;

	# How many bytes the connection must have to be considered potentially
	# a probe.  If missing, then there's no lower/upper bound.
	#
	# Note, the attack that motivated including these was SSH password
	# guessing, where it was empirically determined that connections
	# with > 1KB and < 2KB bytes transferred appear to be unsuccessful
	# password guesses.
	#
	global min_bytes: table[port] of int &default=-1 &redef;
	global max_bytes: table[port] of int &default=-1 &redef;

	# How many tries a given originator host has made against a given
	# port on a given responder host.
	global tries: table[addr, addr, port] of count
					&default=0 &read_expire = 10 min;
}

global reported_hosts: set[addr] &read_expire = 1 day;

function service_probe_check(c: connection)
	{
	if ( ! detect_probes )
		return;

	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;
	local service = (port_names[20/tcp] in c$service) ? 20/tcp : id$resp_p;

	if ( orig in reported_hosts )
		# We've already blocked them.
		return;

	if ( is_local_addr(orig) )
		# We only analyze probes of local servers.
		return;

	if ( service !in probe_ports )
		# Not a port we care about.
		return;

	local enough_bytes = T;
	local bytes_xferred = c$orig$size + c$resp$size;

	if ( service in min_bytes && bytes_xferred < min_bytes[service] )
		enough_bytes = F;

	if ( service in max_bytes && bytes_xferred > max_bytes[service] )
		enough_bytes = F;

	if ( ! enough_bytes )
		return;

	local cnt = ++tries[orig, resp, service];
	if ( cnt == connect_threshold[service] )
		{
		local svc = service_name(c);

		NOTICE([$note=ServiceProbe, $src=orig,
			$msg=fmt("service probing %s -> %s %s",
			orig, resp, svc)]);

		# Since we've dropped this host, we can now release the space.
		delete tries[orig, resp, service];
		add reported_hosts[orig];
		}
	}


event connection_state_remove(c: connection)
	{
	service_probe_check(c);
	}
