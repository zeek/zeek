# $Id: portmapper.bro 4758 2007-08-10 06:49:23Z vern $

@load notice
@load hot
@load conn
@load weird

module Portmapper;

export {
	redef enum Notice += {
		# Some combination of the service looked up, the host doing the
		# request, and the server contacted is considered sensitive.
		SensitivePortmapperAccess,
	};

	# Kudos to Job de Haas for a lot of these entries.

	const rpc_programs = {
		[200] = "aarp",

		[100000] = "portmapper", [100001] = "rstatd",
		[100002] = "rusersd", [100003] = "nfs", [100004] = "ypserv",
		[100005] = "mountd", [100007] = "ypbind", [100008] = "walld",
		[100009] = "yppasswdd", [100010] = "etherstatd",
		[100011] = "rquotad", [100012] = "sprayd",
		[100013] = "3270_mapper", [100014] = "rje_mapper",
		[100015] = "selection_svc", [100016] = "database_svc",
		[100017] = "rexd", [100018] = "alis", [100019] = "sched",
		[100020] = "llockmgr", [100021] = "nlockmgr",
		[100022] = "x25.inr", [100023] = "statmon",
		[100024] = "status", [100026] = "bootparam",
		[100028] = "ypupdate", [100029] = "keyserv",
		[100033] = "sunlink_mapper", [100036] = "pwdauth",
		[100037] = "tfsd", [100038] = "nsed",
		[100039] = "nsemntd", [100041] = "pnpd",
		[100042] = "ipalloc", [100043] = "filehandle",
		[100055] = "ioadmd", [100062] = "NETlicense",
		[100065] = "sunisamd", [100066] = "debug_svc",
		[100068] = "cms", [100069] = "ypxfrd",
		[100071] = "bugtraqd", [100078] = "kerbd",
		[100083] = "tooltalkdb", [100087] = "admind",
		[100099] = "autofsd",

		[100101] = "event", [100102] = "logger", [100104] = "sync",
		[100105] = "diskinfo", [100106] = "iostat",
		[100107] = "hostperf", [100109] = "activity",
		[100111] = "lpstat", [100112] = "hostmem",
		[100113] = "sample", [100114] = "x25", [100115] = "ping",
		[100116] = "rpcnfs", [100117] = "hostif", [100118] = "etherif",
		[100119] = "ippath", [100120] = "iproutes",
		[100121] = "layers", [100122] = "snmp", [100123] = "traffic",
		[100131] = "layers2", [100135] = "etherif2",
		[100136] = "hostmem2", [100137] = "iostat2",
		[100138] = "snmpv2", [100139] = "sender",

		[100221] = "kcms", [100227] = "nfs_acl", [100229] = "metad",
		[100230] = "metamhd", [100232] = "sadmind", [100233] = "ufsd",
		[100235] = "cachefsd", [100249] = "snmpXdmid",

		[100300] = "nisd", [100301] = "nis_cache",
		[100302] = "nis_callback", [100303] = "nispasswd",

		[120126] = "nf_snmd", [120127] = "nf_snmd",

		[150001] = "pcnfsd",

		[300004] = "frameuser", [300009] = "stdfm", [300019] = "amd",

		[300433] = "bssd", [300434] = "drdd",

		[300598] = "dmispd",

		[390100] = "prestoctl_svc",

		[390600] = "arserverd", [390601] = "ntserverd",
		[390604] = "arservtcd",

		[391000] = "SGI_snoopd", [391001] = "SGI_toolkitbus",
		[391002] = "SGI_fam", [391003] = "SGI_notepad",
		[391004] = "SGI_mountd", [391005] = "SGI_smtd",
		[391006] = "SGI_pcsd", [391007] = "SGI_nfs",
		[391008] = "SGI_rfind", [391009] = "SGI_pod",
		[391010] = "SGI_iphone", [391011] = "SGI_videod",
		[391012] = "SGI_testcd", [391013] = "SGI_ha_hb",
		[391014] = "SGI_ha_nc", [391015] = "SGI_ha_appmon",
		[391016] = "SGI_xfsmd", [391017] = "SGI_mediad",

		# 391018 - 391063 = "SGI_reserved"

		[545580417] = "bwnfsd",

		[555555554] = "inetray.start", [555555555] = "inetray",
		[555555556] = "inetray", [555555557] = "inetray",
		[555555558] = "inetray", [555555559] = "inetray",
		[555555560] = "inetray",

		[600100069] = "fypxfrd",

		[1342177279] = "Solaris/CDE",	# = 0x4fffffff

		# Some services that choose numbers but start often at these values.
		[805306368] = "dmispd",
		[824395111] = "cfsd", [1092830567] = "cfsd",
	} &redef;

	const NFS_services = {
		"mountd", "nfs", "pcnfsd", "nlockmgr", "rquotad", "status"
	} &redef;

	# Indexed by the host providing the service, the host requesting it,
	# and the service.
	const RPC_okay: set[addr, addr, string] &redef;
	const RPC_okay_nets: set[subnet] &redef;
	const RPC_okay_services: set[string] &redef;
	const NFS_world_servers: set[addr] &redef;

	# Indexed by the portmapper request and a boolean that's T if
	# the request was answered, F it was attempted but not answered.
	# If there's an entry in the set, then the access won't be logged
	# (unless the connection is hot for some other reason).
	const RPC_do_not_complain: set[string, bool] = {
		["pm_null", [T, F]],
	} &redef;

	# Indexed by the host requesting the dump and the host from which it's
	# requesting it.
	const RPC_dump_okay: set[addr, addr] &redef;

	# Indexed by the host providing the service - any host can request it.
	const any_RPC_okay = {
		[NFS_world_servers, NFS_services],
		[sun-rpc.mcast.net, "ypserv"],	# sigh
	} &redef;
}

redef capture_filters += { ["portmapper"] = "port 111" };

const portmapper_ports = { 111/tcp } &redef;
redef dpd_config += { [ANALYZER_PORTMAPPER] = [$ports = portmapper_ports] };

const portmapper_binpac_ports = { 111/udp } &redef;
redef dpd_config += { [ANALYZER_RPC_UDP_BINPAC] = [$ports = portmapper_binpac_ports] };

# Indexed by source and destination addresses, plus the portmapper service.
# If the tuple is in the set, then we already logged it and shouldn't do
# so again.
global did_pm_log: set[addr, addr, string];

# Indexed by source and portmapper service.  If set, we already logged
# and shouldn't do so again.
global suppress_pm_log: set[addr, string];


function RPC_weird_action_filter(c: connection): Weird::WeirdAction
	{
	if ( c$id$orig_h in RPC_okay_nets )
		return Weird::WEIRD_FILE;
	else
		return Weird::WEIRD_UNSPECIFIED;
	}

redef Weird::weird_action_filters += {
	[["bad_RPC", "excess_RPC", "multiple_RPCs", "partial_RPC"]] =
		RPC_weird_action_filter,
};

function rpc_prog(p: count): string
	{
	if ( p in rpc_programs )
		return rpc_programs[p];
	else
		return fmt("unknown-%d", p);
	}

function pm_check_getport(r: connection, prog: string): bool
	{
	if ( prog in RPC_okay_services ||
	     [r$id$resp_h, prog] in any_RPC_okay ||
	     [r$id$resp_h, r$id$orig_h, prog] in RPC_okay )
		return F;

	if ( r$id$orig_h in RPC_okay_nets )
		return F;

	return T;
	}

function pm_activity(r: connection, log_it: bool, proc: string)
	{
	local id = r$id;

	if ( log_it &&
	     [id$orig_h, id$resp_h, proc] !in did_pm_log &&
	     [id$orig_h, proc] !in suppress_pm_log )
		{
		NOTICE([$note=SensitivePortmapperAccess, $conn=r,
			$msg=fmt("rpc: %s %s: %s",
				id_string(r$id), proc, r$addl)]);
		add did_pm_log[id$orig_h, id$resp_h, proc];
		}
	}

function pm_request(r: connection, proc: string, addl: string, log_it: bool)
	{
	if ( [proc, T] in RPC_do_not_complain )
		log_it = F;

	if ( ! is_tcp_port(r$id$orig_p) )
		{
		# It's UDP, so no connection_established event - check for
		# scanning, hot access, here, instead.
		Scan::check_scan(r, T, F);
		Hot::check_hot(r, Hot::CONN_ESTABLISHED);
		}

	if ( r$addl == "" )
		r$addl = addl;

	else
		{
		if ( byte_len(r$addl) > 80 )
			{
			# r already has a lot of annotation.  We can sometimes
			# get *zillions* of successive pm_request's with the
			# same connection ID, depending on how the RPC client
			# behaves.  For those, don't add any further, except
			# add an ellipses if we don't already have one.
			append_addl(r, "...");
			}
		else
			append_addl_marker(r, addl, ", ");
		}

	add r$service[proc];
	Hot::check_hot(r, Hot::CONN_FINISHED);
	pm_activity(r, log_it || r$hot > 0, proc);
	}


event pm_request_null(r: connection)
	{
	pm_request(r, "pm_null", "", F);
	}

event pm_request_set(r: connection, m: pm_mapping, success: bool)
	{
	pm_request(r, "pm_set", fmt("%s %d (%s)",
		rpc_prog(m$program), m$p, success ? "ok" : "failed"), T);
	}

event pm_request_unset(r: connection, m: pm_mapping, success: bool)
	{
	pm_request(r, "pm_unset", fmt("%s %d (%s)",
		rpc_prog(m$program), m$p, success ? "ok" : "failed"), T);
	}

function update_RPC_server_map(server: addr, p: port, prog: string)
	{
	if ( [server, p] in RPC_server_map )
		{
		if ( prog !in RPC_server_map[server, p] )
			{
			RPC_server_map[server, p] =
				fmt("%s/%s", RPC_server_map[server, p], prog);
			}
		}
	else
		RPC_server_map[server, p] = prog;
	}

event pm_request_getport(r: connection, pr: pm_port_request, p: port)
	{
	local prog = rpc_prog(pr$program);
	local log_it = pm_check_getport(r, prog);

	update_RPC_server_map(r$id$resp_h, p, prog);

	pm_request(r, "pm_getport", fmt("%s -> %s", prog, p), log_it);
	}

function pm_mapping_to_text(server: addr, m: pm_mappings): string
	{
	# Used to suppress multiple entries for multiple versions.
	local mapping_seen: set[count, port];
	local addls: vector of string;
	local num_addls = 0;

	for ( mp in m )
		{
		local prog = m[mp]$program;
		local p = m[mp]$p;

		if ( [prog, p] !in mapping_seen )
			{
			add mapping_seen[prog, p];
			addls[++num_addls] = fmt("%s -> %s", rpc_prog(prog), p);

			update_RPC_server_map(server, p, rpc_prog(prog));
			}
		}

	local addl_str = fmt("%s", sort(addls, strcmp));

	# Lop off surrounding []'s for compatibility with previous
	# format.
	addl_str = sub(addl_str, /^\[/, "");
	addl_str = sub(addl_str, /\]$/, "");

	return addl_str;
	}

event pm_request_dump(r: connection, m: pm_mappings)
	{
	local log_it = [r$id$orig_h, r$id$resp_h] !in RPC_dump_okay;
	pm_request(r, "pm_dump", length(m) == 0 ? "(nil)" : "(done)", log_it);
	append_addl(r, cat("<", pm_mapping_to_text(r$id$resp_h, m), ">"));
	}

event pm_request_callit(r: connection, call: pm_callit_request, p: port)
	{
	local orig_h = r$id$orig_h;
	local prog = rpc_prog(call$program);
	local log_it = [orig_h, prog] !in suppress_pm_log;

	pm_request(r, "pm_callit", fmt("%s/%d (%d bytes) -> %s",
		prog, call$proc, call$arg_size, p), log_it);

	if ( prog == "walld" )
		add suppress_pm_log[orig_h, prog];
	}


function pm_attempt(r: connection, proc: string, status: rpc_status,
			addl: string, log_it: bool)
	{
	if ( [proc, F] in RPC_do_not_complain )
		log_it = F;

	if ( ! is_tcp_port(r$id$orig_p) )
		{
		# It's UDP, so no connection_attempt event - check for
		# scanning here, instead.
		Scan::check_scan(r, F, F);
		Hot::check_hot(r, Hot::CONN_ATTEMPTED);
		}

	add r$service[proc];
	append_addl(r, fmt("(%s)", RPC_status[status]));

	# Current policy is ignore any failed attempts.
	pm_activity(r, F, proc);
	}

event pm_attempt_null(r: connection, status: rpc_status)
	{
	pm_attempt(r, "pm_null", status, "", T);
	}

event pm_attempt_set(r: connection, status: rpc_status, m: pm_mapping)
	{
	pm_attempt(r, "pm_set", status, fmt("%s %d", rpc_prog(m$program), m$p), T);
	}

event pm_attempt_unset(r: connection, status: rpc_status, m: pm_mapping)
	{
	pm_attempt(r, "pm_unset", status, fmt("%s %d", rpc_prog(m$program), m$p), T);
	}

event pm_attempt_getport(r: connection, status: rpc_status, pr: pm_port_request)
	{
	local prog = rpc_prog(pr$program);
	local log_it = pm_check_getport(r, prog);
	pm_attempt(r, "pm_getport", status, prog, log_it);
	}

event pm_attempt_dump(r: connection, status: rpc_status)
	{
	local log_it = [r$id$orig_h, r$id$resp_h] !in RPC_dump_okay;
	pm_attempt(r, "pm_dump", status, "", log_it);
	}

event pm_attempt_callit(r: connection, status: rpc_status,
			call: pm_callit_request)
	{
	local orig_h = r$id$orig_h;
	local prog = rpc_prog(call$program);
	local log_it = [orig_h, prog] !in suppress_pm_log;

	pm_attempt(r, "pm_callit", status,
		fmt("%s/%d (%d bytes)", prog, call$proc, call$arg_size),
		log_it);

	if ( prog == "walld" )
		add suppress_pm_log[orig_h, prog];
	}

event pm_bad_port(r: connection, bad_p: count)
	{
	event conn_weird_addl("bad_pm_port", r, fmt("port %d", bad_p));
	}
