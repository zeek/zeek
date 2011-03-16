# $Id: dyn-disable.bro,v 1.1.4.3 2006/05/31 01:52:02 sommer Exp $
#
# When this script is loaded, analyzers that raise protocol_violation events
# are disabled for the affected connection.

# Note that this a first-shot solution. Eventually, we should make the
# disable-decision more fine-grained/sophisticated.

@load conn
@load notice

module DynDisable;

export {
	redef enum Notice += {
		ProtocolViolation
	};

	# Ignore violations which go this many bytes into the connection.
	const max_volume = 10 * 1024 &redef;
}

global conns: table[conn_id] of set[count];

event protocol_violation(c: connection, atype: count, aid: count,
				reason: string)
	{
	if ( c$id in conns && aid in conns[c$id] )
		return;

	local size = c$orig$size + c$resp$size;

	if ( max_volume > 0 && size > max_volume )
		return;

	# Disable the analyzer that raised the last core-generated event.
	disable_analyzer(c$id, aid);

	NOTICE([$note=ProtocolViolation, $conn=c,
		$msg=fmt("%s analyzer %s disabled due to protocol violation",
				id_string(c$id), analyzer_name(atype)),
		$sub=reason, $n=atype]);

	if ( c$id !in conns )
		conns[c$id] = set();

	add conns[c$id][aid];
	}

event connection_state_remove(c: connection)
	{
	delete conns[$id=c$id];
	}
