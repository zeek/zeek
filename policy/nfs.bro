# $Id$

@load udp

module NFS;

export {
	global log_file = open_log_file("nfs") &redef;
}


redef capture_filters += { 
	["nfs"] = "port 2049",
	# NFS UDP packets are often fragmented.
	["nfs-frag"] = "(ip[6:2] & 0x3fff != 0) and udp",
};

global nfs_ports = { 2049/tcp, 2049/udp } &redef;
redef dpd_config += { [ANALYZER_NFS] = [$ports = nfs_ports] };

# Maps opaque file handles to numbers for easier tracking.
global num_fhs = 0;
global fh_map: table[string] of count;

function map_fh(fh: string): string
	{
	if ( fh !in fh_map )
		fh_map[fh] = ++num_fhs;

	return cat("FH", fh_map[fh]);
	}


function NFS_request(n: connection, req: string, addl: string)
	{
	print log_file, fmt("%.06f %s NFS %s: %s",
				network_time(), id_string(n$id), req, addl);
	}

function NFS_attempt(n: connection, req: string, status: count, addl: string)
	{
	print log_file, fmt("%.06f %s NFS attempt %s (%d): %s",
			network_time(), id_string(n$id), req, status, addl);
	}

function is_success(info: nfs3_info): bool
	{
	return (info$rpc_stat == RPC_SUCCESS && info$nfs_stat == NFS3ERR_OK);
	}

function nfs_get_log_prefix(c: connection, info: nfs3_info, proc: string): string
	{
	local nfs_stat_str = (info$rpc_stat == RPC_SUCCESS) ? fmt("%s", info$nfs_stat) : "X";
	return fmt("%.06f %.06f %d %.06f %.06f %d %s %s %s %s %s", 
			info$req_start, info$req_dur, info$req_len,
			info$rep_start, info$rep_dur, info$rep_len,
			id_string(c$id), get_port_transport_proto(c$id$orig_p),
			proc, info$rpc_stat, nfs_stat_str);
	}

event nfs_proc_not_implemented(c: connection, info: nfs3_info, proc: nfs3_proc) 
	{
	local prefix = nfs_get_log_prefix(c, info, fmt("%s", proc));

	print log_file, fmt("%s Not_implemented", prefix);
	}

event nfs_proc_null(c: connection, info: nfs3_info)
	{
	local prefix = nfs_get_log_prefix(c, info, "null");

	print log_file, prefix;
	}

event nfs_proc_getattr (c: connection, info: nfs3_info, fh: string, attrs: nfs3_fattr) 
	{
	local prefix = nfs_get_log_prefix(c, info, "getattr");

	# TODO: check for success and print attrs, if successful 
	 
	print log_file, fmt("%s %s", prefix, map_fh(fh));
	}

event nfs_proc_lookup(c: connection, info: nfs3_info, req: nfs3_diropargs, rep: nfs3_lookup_reply)
	{
	local prefix = nfs_get_log_prefix(c, info, "lookup");

	if (! is_success(info) )
		{
		print log_file, fmt("%s %s + %s", prefix, map_fh(req$dirfh), req$fname);
		# could print dir_attr, if they are set ....
		return;
		}
	print log_file, fmt("%s %s + %s => %s", prefix, map_fh(req$dirfh), req$fname, map_fh(rep$fh));
	
	}

event nfs_proc_read(c: connection, info: nfs3_info, req: nfs3_readargs, rep: nfs3_read_reply)
	{
	local msg = nfs_get_log_prefix(c, info, "read");

	msg = fmt("%s %s @%.0f: %d", msg, map_fh(req$fh), req$offset, req$size);
	if (is_success(info))
		msg = fmt("%s, got %d bytes %s", msg, rep$size, (rep$eof) ? "<eof>" : "x");

	print log_file, msg;
	}

