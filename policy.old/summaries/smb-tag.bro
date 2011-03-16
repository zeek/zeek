@load conn-util

redef capture_filters += {
	["smb"] = "tcp port 445",
	["netbios-ss"] = "tcp port 139",
};

global smb_filename_tag: table[conn_id] of string &default = "";

const log_smb_tags = T &redef;
function get_smb_tag(id: conn_id): string
	{
	if ( id in smb_filename_tag )
		return smb_filename_tag[id];
	else
		return "";
	}

module SMB_tag;

global log = open_log_file("smb-tag") &redef;

const well_known_files = {
	"\\IPC$",
	"\\print$",
	"\\LANMAN",
	"\\atsvc",
	"\\AudioSrv",
	"\\browser",
	"\\cert",
	"\\Ctx_Winstation_API_Service",
	"\\DAV",
	"\\dnsserver",
	"\\epmapper",
	"\\eventlog",
	"\\HydraLsPipe",
	"\\InitShutdown",
	"\\keysvc",
	"\\locator",
	"\\llsrpc",
	"\\lsarpc",
	"\\msgsvc",
	"\\netdfs",
	"\\netlogon",
	"\\ntsvcs",
	"\\policyagent",
	"\\ipsec",
	"\\ProfMapApi",
	"\\protected_storage",
	"\\ROUTER",
	"\\samr",
	"\\scerpc",
	"\\SECLOGON",
	"\\SfcApi",
	"\\spoolss",
	"\\srvsvc",
	"\\ssdpsrv",
	"\\svcctl",
	"\\tapsrv",
	"\\trkwks",
	"\\W32TIME",
	"\\W32TIME_ALT",
	"\\winlogonrpc",
	"\\winreg",
	"\\winspipe",
	"\\wkssvc",
	"\\lbl.gov",
	"\\LBL"
};

function well_known_file(n: string): string
	{
	n = to_lower(n);
	local a = "";
	for ( p in well_known_files )
		{
		if ( strstr(n, to_lower(p)) > 0 )
			if ( byte_len(p) > byte_len(a) )
				a = p;
		}
	return a;
	}

function add_to_smb_filename_tag(c: connection, name: string): bool
	{
	if ( name == "\\PIPE\\" || name == "" )
		return F;

	local id = c$id;
	local orig_tag = smb_filename_tag[id];

	local n = well_known_file(name);
	if ( n == "" )
		{
		if ( log_smb_tags )
			print log, fmt("%.6f %s regular file: \"%s\"",
				network_time(), conn_id_string(c$id), name);
		n = "<file>";
		}

	n = fmt("\"%s\"", n);

	if ( orig_tag == "" )
		{
		smb_filename_tag[id] = n;
		}
	else if ( strstr(orig_tag, n) == 0 )
		{
		smb_filename_tag[id] = cat(orig_tag, ",", n);
		}

	return T;
	}

event smb_com_nt_create_andx(c: connection, name: string)
	{
	add_to_smb_filename_tag(c, name);
	}

event smb_com_transaction(c: connection, is_orig: bool, subcmd: count,
		name: string, data: string)
	{
	add_to_smb_filename_tag(c, name);
	}

event smb_com_transaction2(c: connection, is_orig: bool, subcmd: count,
		name: string, data: string)
	{
	add_to_smb_filename_tag(c, name);
	}

event smb_get_dfs_referral(c: connection, max_referral_level: count, file_name: string)
	{
	add_to_smb_filename_tag(c, file_name);
	}

event smb_com_tree_connect_andx(c: connection, path: string, service: string)
	{
	local basic = sub(path, /.*\\/, "\\");
	if ( /\$$/ in basic )
		add_to_smb_filename_tag(c, basic);
	}

event delete_smb_tag(c: connection)
	{
	delete smb_filename_tag[c$id];
	}

event connection_state_remove(c: connection)
	{
	if ( c$id in smb_filename_tag )
		{
		if ( log_smb_tags )
			print log, fmt("conn %s start %.6f SMB [%s]",
				conn_id_string(c$id),
				c$start_time,
				smb_filename_tag[c$id]);
		event delete_smb_tag(c);
		}
	}
