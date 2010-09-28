# $Id: demux.bro 4758 2007-08-10 06:49:23Z vern $

const demux_dir = log_file_name("xscript") &redef;
global created_demux_dir = F;

# Table of which connections we're demuxing.
global demuxed_conn: set[conn_id];

# tag: identifier to use for the reason for demuxing
# otag: identifier to use for originator side of the connection
# rtag: identifier to use for responder side of the connection
function demux_conn(id: conn_id, tag: string, otag: string, rtag: string): bool
	{
	if ( id in demuxed_conn || ! active_connection(id) )
		return F;

	if ( ! created_demux_dir )
		{
		mkdir(demux_dir);
		created_demux_dir = T;
		}

	local orig_file =
		fmt("%s/%s.%s.%s.%d-%s.%d", demux_dir, otag, tag,
			id$orig_h, id$orig_p, id$resp_h, id$resp_p);
	local resp_file =
		fmt("%s/%s.%s.%s.%d-%s.%d", demux_dir, rtag, tag,
			id$resp_h, id$resp_p, id$orig_h, id$orig_p);

	set_contents_file(id, CONTENTS_ORIG, open(orig_file));
	set_contents_file(id, CONTENTS_RESP, open(resp_file));

	add demuxed_conn[id];

	return T;
	}

event connection_finished(c: connection)
	{
	delete demuxed_conn[c$id];
	}
