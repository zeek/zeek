# @TEST-EXEC: zeek -b -r $TRACES/mount/mount_base.pcap %INPUT
# @TEST-EXEC: btest-diff .stdout

global mount_ports: set[port] = { 635/tcp, 635/udp, 20048/tcp, 20048/udp } &redef;
redef ignore_checksums = T;

event zeek_init()
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_MOUNT, mount_ports);
	Analyzer::enable_analyzer(Analyzer::ANALYZER_MOUNT);
	}

event mount_proc_mnt(c: connection, info: MOUNT3::info_t, req: MOUNT3::dirmntargs_t, rep: MOUNT3::mnt_reply_t)
	{
	print(fmt("mount_proc_mnt: %s\n\t%s\n\t%s\n\t%s\n", c, info, req, rep));
	}

event mount_proc_umnt(c: connection, info: MOUNT3::info_t, req: MOUNT3::dirmntargs_t)
	{
	print(fmt("mount_proc_umnt: %s\n\t%s\n\t%s\n", c, info, req));
	}

event mount_proc_umnt_all(c: connection, info: MOUNT3::info_t, req: MOUNT3::dirmntargs_t)
	{
	print(fmt("mount_proc_umnt_all: %s\n\t%s\n\t%s\n", c, info, req));
	}

event mount_proc_not_implemented(c: connection, info: MOUNT3::info_t, proc: MOUNT3::proc_t)
	{
	print(fmt("mount_proc_not_implemented: %s\n\t%s\n\t%s\n", c, info, proc));
	}
