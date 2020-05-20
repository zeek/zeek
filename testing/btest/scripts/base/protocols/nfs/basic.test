# @TEST-EXEC: zeek -b -r $TRACES/nfs/nfs_base.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout

global nfs_ports: set[port] = { 2049/tcp, 2049/udp } &redef;
redef ignore_checksums = T;

event zeek_init()
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_NFS, nfs_ports);
	Analyzer::enable_analyzer(Analyzer::ANALYZER_NFS);
	}

event nfs_proc_lookup(c: connection , info: NFS3::info_t , req: NFS3::diropargs_t , rep: NFS3::lookup_reply_t )
	{
	print(fmt("nfs_proc_lookup: %s\n\t%s\n\t%s\n\t%s\n", c, info, req, rep));
	}

event nfs_proc_read(c: connection , info: NFS3::info_t , req: NFS3::readargs_t , rep: NFS3::read_reply_t )
	{
	print(fmt("nfs_proc_read: %s\n\t%s\n\t%s\n\t%s\n", c, info, req, rep));
	}

event nfs_proc_readlink(c: connection , info: NFS3::info_t , fh: string , rep: NFS3::readlink_reply_t )
	{
	print(fmt("nfs_proc_readlink: %s\n\t%s\n\t%s\n\t%s\n", c, info, fh, rep));
	}

event nfs_proc_write(c: connection , info: NFS3::info_t , req: NFS3::writeargs_t , rep: NFS3::write_reply_t )
	{
	print(fmt("nfs_proc_write: %s\n\t%s\n\t%s\n\t%s\n", c, info, req, rep));
	}

event nfs_proc_create(c: connection , info: NFS3::info_t , req: NFS3::diropargs_t , rep: NFS3::newobj_reply_t )
	{
	print(fmt("nfs_proc_create: %s\n\t%s\n\t%s\n\t%s\n", c, info, req, rep));
	}

event nfs_proc_mkdir(c: connection , info: NFS3::info_t , req: NFS3::diropargs_t , rep: NFS3::newobj_reply_t )
	{
	print(fmt("nfs_proc_mkdir: %s\n\t%s\n\t%s\n\t%s\n", c, info, req, rep));
	}

event nfs_proc_remove(c: connection , info: NFS3::info_t , req: NFS3::diropargs_t , rep: NFS3::delobj_reply_t )
	{
	print(fmt("nfs_proc_remove: %s\n\t%s\n\t%s\n\t%s\n", c, info, req, rep));
	}

event nfs_proc_rmdir(c: connection , info: NFS3::info_t , req: NFS3::diropargs_t , rep: NFS3::delobj_reply_t )
	{
	print(fmt("nfs_proc_rmdir: %s\n\t%s\n\t%s\n\t%s\n", c, info, req, rep));
	}

event nfs_proc_readdir(c: connection , info: NFS3::info_t , req: NFS3::readdirargs_t , rep: NFS3::readdir_reply_t )
	{
	print(fmt("nfs_proc_readdir: %s\n\t%s\n\t%s\n\t%s\n", c, info, req, rep));
	}

event nfs_proc_rename(c: connection , info: NFS3::info_t , req: NFS3::renameopargs_t , rep: NFS3::renameobj_reply_t )
	{
	print(fmt("nfs_proc_rename: %s\n\t%s\n\t%s\n\t%s\n", c, info, req, rep));
	}

event nfs_proc_sattr(c: connection, info: NFS3::info_t, req: NFS3::sattrargs_t, rep: NFS3::sattr_reply_t)
	{
	print(fmt("nfs_proc_sattr: %s\n\t%s\n\t%s\n\t%s\n", c, info, req, rep));
	}

event nfs_proc_link(c: connection, info: NFS3::info_t, req: NFS3::linkargs_t, rep: NFS3::link_reply_t)
	{
	print(fmt("nfs_proc_link: %s\n\t%s\n\t%s\n\t%s\n", c, info, req, rep));
	}

event nfs_proc_symlink(c: connection, info: NFS3::info_t, req: NFS3::symlinkargs_t, rep: NFS3::newobj_reply_t)
	{
	print(fmt("nfs_proc_symlink: %s\n\t%s\n\t%s\n\t%s\n", c, info, req, rep));
	}

event nfs_proc_not_implemented(c: connection , info: NFS3::info_t , proc: NFS3::proc_t )
	{
	print(fmt("nfs_proc_not_implemented: %s\n\t%s\n\t%s\n", c, info, proc));
	}

