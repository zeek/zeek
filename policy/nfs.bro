# $Id$

@load udp


module NFS3;

export {
	global log_file = open_log_file("nfs") &redef;
	global names_log_file = open_log_file("nfs-files") &redef;

	# we want to estiamte how long it takes to lookup a chain of FH 
	# (directories) until we reach a FH that is used in a read or write 
	# operation. Whenever we get a new FH, we check how long ago we 
	# got the FH's parent. If this is less than fh_chain_maxtime, we 
	# assume that they belong to a lookup chain and set the dt value for
	# the FH accordingly. 
	global fh_chain_maxtime = 100 msec;
}


redef capture_filters += { 
	["nfs"] = "port 2049",
	# NFS UDP packets are often fragmented.
	["nfs-frag"] = "(ip[6:2] & 0x3fff != 0) and udp",
};

global nfs_ports = { 2049/tcp, 2049/udp } &redef;
redef dpd_config += { [ANALYZER_NFS] = [$ports = nfs_ports] };

# Information about a filehandle
type fh_info : record { 
	id: count;   # A unique ID (counter) for more readable representation of the FH
	pathname: string &default="@"; # the path leading to this FH
	basename: string &default="";  # the name of this FHs file or directory
	t0: time &default=double_to_time(0); # time when we first saw this FH
	dt: interval &default=0 sec;   # time it took to get this FH (assuming a chain of 
	                               # procedures that ultimately yield the FH for the file
								   # a client is interested in
	chainlen: count &default=0;
	attr: fattr_t &optional;
};

# Maps opaque file handles to numbers for easier tracking.
global num_fhs = 0;
global fh_map: table[addr,string] of fh_info;

# Maps connids to number for easier post processing
global num_nfs_conns = 0;
global nfs_conns: table[conn_id] of count;


# Get the FH info. Create a new info if it doesn't exists
function get_fh_info(c: connection, fh: string): fh_info
	{
	if ( [c$id$resp_h, fh] !in fh_map )
		{
		# Don't have a mapping for this FH yet. E.g., a root FH
		local newfhinfo: fh_info = [ $id=++num_fhs ];
		newfhinfo$pathname = fmt("@%d", newfhinfo$id);
		newfhinfo$t0 = network_time();
		fh_map[c$id$resp_h, fh] = newfhinfo;
		}
	return fh_map[c$id$resp_h, fh];
	}

function log_filename(info: fh_info) 
	{
	print names_log_file, fmt("%.6f path FH%d %s/%s", network_time(), info$id, info$pathname, info$basename);
	##print fmt("%.6f FH%d <%s> <%s>", network_time(), info$id, info$pathname, info$basename);
	}

function fmt_attr(a: fattr_t): string
	{
	local s = fmt("%s %s %d %d %d %d %d %d %d %d %d %.2f %.2f %.2f", 
			a$ftype, mode2string(a$mode), a$nlink, a$uid, a$gid, a$size, a$used, a$rdev1, a$rdev2,
			a$fsid, a$fileid, a$atime, a$mtime, a$ctime);
	return s;
	}

function log_attributes(c: connection, fh: string, attr: fattr_t)
	{
	local info = get_fh_info(c,fh);
	local did_change = F;
	# check whether the attributes have changes 
	if (info?$attr) 
		{
		# We can't compare records for equality :-(. So we use a hack. 
		# We add the two instance we want to compare to a set. If there 
		# are two elements in the set, the records are not equal...
		local dummy: set[fattr_t];
		add dummy[info$attr];
		add dummy[attr];
		if (|dummy| > 1)
			did_change = T;
		}
	else
		did_change=T;
	if (did_change)
		{
		info$attr = attr;
		print names_log_file, fmt("%.6f attr FH%d %s", network_time(), info$id, fmt_attr(attr));
		}
	}

# Update (or add) a filehandle mapping.
#   parentfh ... parent (directory) 
#   name ....... the name for this FH
#   fh ......... the new FH
function add_update_fh(c: connection, parentfh: string, name: string, fh: string)
	{
	local info = get_fh_info(c, fh);

	# TODO: we could/should check if we already have a pathname and/or basename
	# for this FH and if so whether it matches the parent we just got!
	info$basename = name;
	if (parentfh != "") 
		{
		local parentinfo = get_fh_info(c, parentfh);
		info$pathname = cat(parentinfo$pathname, "/", parentinfo$basename);
		if ( (network_time() - parentinfo$t0) < fh_chain_maxtime 
				&& info$dt < 0 sec )
			{
			# The FH is part of lookup chain and it doesn't yet have a dt value
			# TODO: this should probably be moved to get_fh_info(). But then get_fh_info()
			# would need information about a FH's parent....
			# TODO: We are using network_time(), but we really should use request
			# and reply time!!!
			info$dt = parentinfo$dt + (network_time() - parentinfo$t0);
			info$chainlen = parentinfo$chainlen + 1;
			}
		}
	log_filename(info);
	}

# Get the total time of the lookup chain for this FH to the 
# current network time. Returns a negative interal if no 
# lookup chain was found
function get_fh_chaintime_str(c:connection, fh:string): string
	{
	local info = get_fh_info(c, fh);
	if ((network_time() - info$t0) < fh_chain_maxtime)
		return fmt("%d %.6f", info$chainlen, info$dt + (network_time() - info$t0));
	else 
		return fmt("%d %.6f", 0, 0.0);
	}

# Get a FH ID
function get_fh_id(c:connection, fh: string): string
	{
	return cat("FH", get_fh_info(c, fh)$id);
	}

# Get the basename for the FH
function get_fh_basename(c:connection, fh: string): string
	{
	return get_fh_info(c, fh)$basename;
	}

# Get the fullname for the FH
function get_fh_fullname(c:connection, fh: string): string
	{
	local info = get_fh_info(c, fh);
	return cat(info$pathname, "/", info$basename);
	}

function print_attr(attr: fattr_t): string
	{
	return fmt("%s", attr);
	}

function map_conn(cid: conn_id): count 
	{
	if (cid !in nfs_conns)
		nfs_conns[cid] = ++num_nfs_conns;
	return nfs_conns[cid];
	}


function is_success(info: info_t): bool
	{
	return (info$rpc_stat == RPC_SUCCESS && info$nfs_stat == NFS3ERR_OK);
	}

function nfs_get_log_prefix(c: connection, info: info_t, proc: string): string
	{
	local nfs_stat_str = (info$rpc_stat == RPC_SUCCESS) ? fmt("%s", info$nfs_stat) : "X";
	return fmt("%.06f %.06f %d %.06f %.06f %d %s %s %d %s %s %s", 
			info$req_start, info$req_dur, info$req_len,
			info$rep_start, info$rep_dur, info$rep_len,
			id_string(c$id), get_port_transport_proto(c$id$orig_p),
			map_conn(c$id), 
			proc, info$rpc_stat, nfs_stat_str);
	}

event nfs_proc_not_implemented(c: connection, info: info_t, proc: NFS3::proc_t) 
	{
	local prefix = nfs_get_log_prefix(c, info, fmt("%s", proc));

	print log_file, fmt("%s Not_implemented", prefix);
	}

event nfs_proc_null(c: connection, info: info_t)
	{
	local prefix = nfs_get_log_prefix(c, info, "null");

	print log_file, prefix;
	}

event nfs_proc_getattr (c: connection, info: info_t, fh: string, attrs: NFS3::fattr_t) 
	{
	local prefix = nfs_get_log_prefix(c, info, "getattr");

	if (is_success(info))
		log_attributes(c, fh, attrs);
	 
	print log_file, fmt("%s %s", prefix, get_fh_id(c,fh));
	}

event nfs_proc_lookup(c: connection, info: info_t, req: NFS3::diropargs_t, rep: NFS3::lookup_reply_t)
	{
	local prefix = nfs_get_log_prefix(c, info, "lookup");

	if (! is_success(info) )
		{
		print log_file, fmt("%s %s + %s", prefix, get_fh_id(c, req$dirfh), req$fname);
		# could print dir_attr, if they are set ....
		return;
		}
	if (rep?$dir_attr)
		log_attributes(c, req$dirfh, rep$dir_attr);
	if (rep?$file_attr)
		log_attributes(c, rep$fh, rep$file_attr);
	add_update_fh(c, req$dirfh, req$fname, rep$fh);
	print log_file, fmt("%s %s + %s => %s", prefix, get_fh_id(c, req$dirfh), req$fname, get_fh_id(c, rep$fh));
	
	}

event nfs_proc_read(c: connection, info: info_t, req: NFS3::readargs_t, rep: NFS3::read_reply_t)
	{
	local msg = nfs_get_log_prefix(c, info, "read");

	msg = fmt("%s %s @%d: %d", msg, get_fh_id(c, req$fh), req$offset, req$size);
	if (is_success(info))
		{
		msg = fmt("%s got %d bytes %s %s", msg, rep$size, (rep$eof) ? "<eof>" : "x", 
					get_fh_chaintime_str(c, req$fh));
		if (rep?$attr)
			log_attributes(c, req$fh, rep$attr);
		}

	print log_file, msg;
	}

event nfs_proc_readlink(c: connection, info: info_t, fh: string, rep: NFS3::readlink_reply_t) 
	{
	local msg = nfs_get_log_prefix(c, info, "readlink");

	msg = fmt("%s %s", msg, get_fh_id(c, fh));
	if (is_success(info))
		{
		msg = fmt("%s : %s", msg, rep$nfspath);
		if (rep?$attr)
			log_attributes(c, fh, rep$attr);
		}

	print log_file, msg;
	}

event nfs_proc_write(c: connection, info: info_t, req: NFS3::writeargs_t, rep: NFS3::write_reply_t)
	{
	local msg = nfs_get_log_prefix(c, info, "write");

	msg = fmt("%s %s @%d: %d %s", msg, get_fh_id(c, req$fh), req$offset, req$size, req$stable);
	if (is_success(info))
		{
		msg = fmt("%s wrote %d bytes %s %s", msg, rep$size, rep$commited, 
					get_fh_chaintime_str(c, req$fh));
		if (rep?$postattr)
			log_attributes(c, req$fh, rep$postattr);
		}

	print log_file, msg;
	}

event connection_state_remove(c: connection)
	{
	if ( c$id !in nfs_conns )
		return;
	delete nfs_conns[c$id];
	}
