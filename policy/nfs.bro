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

function nfs_get_log_prefix(c: connection, rpc_stat: rpc_status, nfs_stat: nfs3_status, proc: string): string
	{
	local nfs_stat_str = (rpc_stat == RPC_SUCCESS) ? fmt("%s", nfs_stat) : "X";
	return fmt("%.06f %s %s %s %s", network_time(), id_string(c$id),
			proc, rpc_stat, nfs_stat_str);
	}

event nfs_proc_not_implemented(c: connection, rpc_stat: rpc_status, nfs_stat: nfs3_status, proc: nfs3_proc) 
	{
	local prefix = nfs_get_log_prefix(c, rpc_stat, nfs_stat, fmt("%s", proc));

	print log_file, fmt("%s Not_implemented", prefix);
	}

event nfs_proc_null(c: connection, rpc_stat: rpc_status, nfs_stat: nfs3_status)
	{
	local prefix = nfs_get_log_prefix(c, rpc_stat, nfs_stat, "null");

	print log_file, prefix;
	}

event nfs_proc_getattr (c: connection, rpc_stat: rpc_status, nfs_stat: nfs3_status, fh: string, attrs: nfs3_fattr) 
	{
	local prefix = nfs_get_log_prefix(c, rpc_stat, nfs_stat, "getattr");

	# TODO: check for success and print attrs, if successful 
	 
	print log_file, fmt("%s %s", prefix, map_fh(fh));
	}

event nfs_proc_lookup(c: connection, rpc_stat: rpc_status, nfs_stat: nfs3_status, req: nfs3_diropargs, rep: nfs3_lookup_reply)
	{
	local prefix = nfs_get_log_prefix(c, rpc_stat, nfs_stat, "lookup");

	if (! (rpc_stat == RPC_SUCCESS && nfs_stat == NFS3ERR_OK) )
		{
		print log_file, fmt("%s %s + %s", prefix, map_fh(req$dirfh), req$fname);
		# could print dir_attr, if they are set ....
		return;
		}
	print log_file, fmt("%s %s + %s => %s", prefix, map_fh(req$dirfh), req$fname, map_fh(rep$fh));
	
	}

event nfs_proc_read(c: connection, rpc_stat: rpc_status, nfs_stat: nfs3_status, req: nfs3_readargs, rep: nfs3_read_reply)
	{
	local msg = nfs_get_log_prefix(c, rpc_stat, nfs_stat, "read");

	msg = fmt("%s %s @%.0f: %d", msg, map_fh(req$fh), req$offset, req$size);
	if (rpc_stat == RPC_SUCCESS && nfs_stat == NFS3ERR_OK)
		msg = fmt("%s, got %d bytes %s", msg, rep$size, (rep$eof) ? "<eof>" : "x");

	print log_file, msg;
	}

