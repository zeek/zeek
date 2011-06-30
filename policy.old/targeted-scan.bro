# $Id:$
#
# Drop external hosts that continually bang away on a particular open port.
#
# Note that we time out identified scanners to avoid excessive memory
# utilitization in the event of a wide scan across address space.

@load notice
@load site

module TargetedScan;

export {
	redef enum Notice += { TargetedScan, };

	# If true, then only consider traffic from external sources.
	global external_only = T &redef;

	# Which ports to consider.
	const ports = { 1433/tcp, } &redef;

	# If set, at least/most this many bytes need to be transferred for
	# a connection using the given port.  These are useful for example
	# for inferring that SSH connections reflect password-guessing
	# attempts.
	const min_bytes: table[port] of count &redef;
	const max_bytes: table[port] of count &redef;

	# If set, then this is the threshold for reportin accessing
	# for a given service.
	const port_threshold: table[port] of count &redef;

	# Otherwise, this is the threshold.
	const general_threshold = 1000 &redef;

	# The data structure we use to track targeted probing.
	# It's exported to enable redef'ing the &write_expire value.
	global targeted_tries: table[addr, addr, port] of count
		&default=0 &write_expire=10 min &redef;
}

function delete_targeted_data(orig: addr, resp: addr, service: port)
	{
	delete targeted_tries[orig, resp, service];
	}

function targeted_check(c: connection)
	{
	local id = c$id;
	local orig = id$orig_h;
	local resp = id$resp_h;
	local service = ("ftp-data" in c$service) ? 20/tcp : id$resp_p;

	if ( service !in ports || (external_only && is_local_addr(orig)) )
		return;

	local bytes_xferred = c$orig$size + c$resp$size;

	if ( service in min_bytes && bytes_xferred < min_bytes[service] )
		return;
	if ( service in max_bytes && bytes_xferred > max_bytes[service] )
		return;

	local cnt = ++targeted_tries[orig, resp, service];

	if ( service in port_threshold )
		{
		if ( cnt != port_threshold[service] )
			return;
		}

	else if ( cnt != general_threshold )
		return;
		
	local svc = service in port_names ?
			port_names[service] : fmt("%s", service);

	NOTICE([$note=TargetedScan, $src=orig, $dst=resp, $p=service,
		$msg=fmt("targeted attack on service %s, count = %d", svc, cnt)]);

	# Since we've reported this host, we can stop tracking it.
	delete targeted_tries[orig, resp, service];
	}


event connection_finished(c: connection)
	{
	targeted_check(c);
	}

event connection_rejected(c: connection)
	{
	targeted_check(c);
	}

event connection_half_finished(c: connection)
	{
	targeted_check(c);
	}

event connection_reset(c: connection)
	{
	targeted_check(c);
	}

event connection_partial_close(c: connection)
	{
	targeted_check(c);
	}

event connection_state_remove(c: connection)
	{
	targeted_check(c);
	}
