# $Id: nfs.bro 4017 2007-02-28 07:11:54Z vern $

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


event nfs_request_null(n: connection)
	{
	NFS_request(n, "null", "");
	}

event nfs_attempt_null(n: connection, status: count)
	{
	NFS_attempt(n, "null", status, "");
	}


event nfs_request_getattr(n: connection, fh: string, attrs: nfs3_attrs)
	{
	NFS_request(n, "getattr", fmt("%s -> %s", map_fh(fh), attrs));
	}

event nfs_attempt_getattr(n: connection, status: count, fh: string)
	{
	NFS_attempt(n, "getattr", status, map_fh(fh));
	}


function opt_attr_fmt(a: nfs3_opt_attrs): string
	{
	return a?$attrs ? fmt("%s", a$attrs) : "<missing>";
	}

event nfs_request_lookup(n: connection, req: nfs3_lookup_args, rep: nfs3_lookup_reply)
	{
	NFS_request(n, "lookup", fmt("%s -> %s (file-attr: %s, dir-attr: %s)",
			req, rep$fh,
			opt_attr_fmt(rep$file_attr),
			opt_attr_fmt(rep$dir_attr)));
	}

event nfs_attempt_lookup(n: connection, status: count, req: nfs3_lookup_args)
	{
	NFS_attempt(n, "lookup", status, fmt("%s", req));
	}


event nfs_request_fsstat(n: connection, root_fh: string, stat: nfs3_fsstat)
	{
	NFS_request(n, "fsstat", fmt("%s -> attr: %s, tbytes: %s, fbytes: %s, abytes: %s, tfiles: %s, ffiles: %s, afiles: %s, invarsec: %s",
		map_fh(root_fh),
		opt_attr_fmt(stat$attrs),
		stat$tbytes, stat$fbytes, stat$abytes,
		stat$tfiles, stat$ffiles, stat$afiles,
		stat$invarsec));
	}

event nfs_attempt_fsstat(n: connection, status: count, root_fh: string)
	{
	NFS_attempt(n, "fsstat", status, map_fh(root_fh));
	}
