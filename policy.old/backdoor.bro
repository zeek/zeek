# $Id: backdoor.bro 4909 2007-09-24 02:26:36Z vern $

# Looks for a variety of applications running on ports other than
# their usual ports.
#
# Note that this script by itself does *not* change capture_filters
# to add in the extra ports to look at.  You need to specify that
# separately.


# Some tcpdump filters can be used to replace or work together with
# some detection algorithms.  They could be used with the "secondary
# filter" for more efficient (but in some cases potentially less reliable)
# matching:
#
# - looking for "SSH-1." or "SSH-2." at the beginning of the packet;
#   somewhat weaker than ssh-sig in that ssh-sig only looks for such
#   pattern in the first packet of a connection:
#
#	tcp[(tcp[12]>>2):4] = 0x5353482D and
#	(tcp[((tcp[12]>>2)+4):2] = 0x312e or tcp[((tcp[12]>>2)+4):2] = 0x322e)
#
# - looking for pkts with 8k+4 (<=128) bytes of data (combined with ssh-len);
#   only effective for ssh 1.x:
#
#	(ip[2:2] - ((ip[0]&0x0f)<<2) - (tcp[12]>>2)) & 0xFF87 = 4
#
# - looking for packets with <= 512 bytes of data that ends with a NUL
#   (can be potentially combined with rlogin-sig or rlogin-sig-1byte):
#
#	(tcp[(ip[2:2] - ((ip[0]&0x0f)<<2))-1] == 0) and
#	((ip[2:2] - ((ip[0]&0x0f)<<2) - (tcp[12]>>2)) != 0) and
#	((ip[2:2] - ((ip[0]&0x0f)<<2) - (tcp[12]>>2)) <= 512)
#
# - looking for telnet negotiation (can be combined with telnet-sig(-3byte)):
#
#	(tcp[(tcp[12]>>2):2] > 0xfffa) and
#	(tcp[(tcp[12]>>2):2] < 0xffff) and
#	((ip[2:2] - ((ip[0]&0x0f)<<2) - (tcp[12] >> 2)) >= 3)
#
# - looking for packets with <= 20 bytes of data (combined with small-pkt):
#
#	(ip[2:2] - ((ip[0]&0x0f)<<2) - (tcp[12]>>2)) <= 20
#
# - looking for FTP servers by the initial "220-" or "220 " sent by the server:
#
#	tcp[(tcp[12]>>2):4] = 0x3232302d or tcp[(tcp[12]>>2):4] = 0x32323020
#
# - looking for root backdoors by seeing a server payload of exactly "# ":
#
#	tcp[(tcp[12]>>2):2] = 0x2320 and
#	(ip[2:2] - ((ip[0]&0x0f)<<2) - (tcp[12]>>2)) == 2
#
# - looking for Napster by the initial "GET" or "SEND" sent by the originator:
#
#	((ip[2:2]-((ip[0]&0x0f)<<2)-(tcp[12]>>2))=4 and
#	tcp[(tcp[12]>>2):4]=0x53454e44) or
#	((ip[2:2]-((ip[0]&0x0f)<<2)-(tcp[12]>>2))=3 and
#	tcp[(tcp[12]>>2):2]=0x4745 and tcp[(tcp[12]>>2)+2]=0x54)
#
# - looking for Gnutella handshaking "GNUTELLA "
#
#	tcp[(tcp[12]>>2):4] = 0x474e5554 and
#	tcp[(4+(tcp[12]>>2)):4] = 0x454c4c41 and
#	tcp[8+(tcp[12]>>2)] = 0x20
#
# - looking for KaZaA via "GIVE " (not present in all connections)
#
#	tcp[(tcp[12]>>2):4] = 0x47495645 and
#	tcp[(4+(tcp[12]>>2)):1] = 0x20
#

@load site
@load port-name
@load demux
@load notice

redef enum Notice += { BackdoorFound, };

# Set to dump the packets that trigger the backdoor detector to a file.
const dump_backdoor_packets = F &redef;

redef backdoor_stat_period = 60 sec;
redef backdoor_stat_backoff = 2.0;

const ssh_min_num_pkts = 8 &redef;
const ssh_min_ssh_pkts_ratio = 0.6 &redef;

const backdoor_min_num_lines = 2 &redef;
const backdoor_min_normal_line_ratio = 0.5 &redef;

const backdoor_min_bytes = 10 &redef;
const backdoor_min_7bit_ascii_ratio = 0.75 &redef;

type rlogin_conn_info : record {
	o_num_null: count;
	o_len: count;
	r_num_null: count;
	r_len: count;
};

const backdoor_demux_disabled = T &redef;
const backdoor_demux_skip_tags: set[string] &redef;

const ftp_backdoor_sigs = "ftp-sig";
const ssh_backdoor_sigs = { "ssh-sig", "ssh-len-v1.x", "ssh-len-v2.x" };
const rlogin_backdoor_sigs = { "rlogin-sig", "rlogin-sig-1byte" };
const root_backdoor_sigs = "root-bd-sig";
const telnet_backdoor_sigs = { "telnet-sig", "telnet-sig-3byte" };
const napster_backdoor_sigs = "napster-sig";
const gnutella_backdoor_sigs = "gnutella-sig";
const kazaa_backdoor_sigs = "kazaa-sig";
const http_backdoor_sigs = "http-sig";
const http_proxy_backdoor_sigs = "http-proxy-sig";
const smtp_backdoor_sigs = "smtp-sig";
const irc_backdoor_sigs = "irc-sig";
const gaobot_backdoor_sigs = "gaobot-sig";

# List of backdoors, so you can use it when defining sets and tables
# with values over all of them.
const backdoor_sigs = {
	ftp_backdoor_sigs, ssh_backdoor_sigs, rlogin_backdoor_sigs,
	root_backdoor_sigs, telnet_backdoor_sigs,
	napster_backdoor_sigs, gnutella_backdoor_sigs, kazaa_backdoor_sigs,
	http_backdoor_sigs, http_proxy_backdoor_sigs,
	smtp_backdoor_sigs, irc_backdoor_sigs, gaobot_backdoor_sigs,
};

# List of address-port pairs that if present in a backdoor are ignored.
# Note that these can be either the client and its source port (unusual)
# or the server and its service port (the common case).
const backdoor_ignore_host_port_pairs: set[addr, port] &redef;

const backdoor_ignore_ports: table[string, port] of bool = {
	# The following ignore backdoors that are detected on their
	# usual ports.  The definitions for ftp-sig, telnet-sig and
	# telnet-sig-3byte are somehwat broad since those backdoors
	# are also frequently triggered for other similar protocols.

	[ftp_backdoor_sigs, [ftp, smtp, 587/tcp ]] = T,
	[ssh_backdoor_sigs, ssh] = T,
	[rlogin_backdoor_sigs , [512/tcp, rlogin, 514/tcp]] = T,
	[root_backdoor_sigs, [telnet, 512/tcp, rlogin, 514/tcp]] = T,
	[telnet_backdoor_sigs, [telnet, ftp, smtp, 143/tcp, 110/tcp]] = T,

	# The following don't have well-known ports (well, Napster does
	# somewhat, as shown below), hence the definitions are F rather
	# than T.
	[napster_backdoor_sigs, [6688/tcp, 6699/tcp]] = F,
	[gnutella_backdoor_sigs, 6346/tcp] = F,

	[kazaa_backdoor_sigs, 1214/tcp] = F,

	[http_backdoor_sigs, [http, 8000/tcp, 8080/tcp]] = T,

	[smtp_backdoor_sigs, [smtp, 587/tcp]] = T,

	# Skip FTP, as "USER foo" generates false positives.  There's
	# also a lot of IRC on 7000/tcp.
	[irc_backdoor_sigs, [ftp, 6666/tcp, 6667/tcp, 7000/tcp]] = T,

	# The following are examples of wildcards, and since they're defined
	# to be F, they don't affect the policy unless redefined.
	["*", http] = F,	# entry for "any backdoor, service http"
	["ssh-sig", 0/tcp] = F,	# entry for "ssh-sig, any port"

} &redef &default = F;

# Indexed by the backdoor, indicates which backdoors residing on
# a local (remote) host should be ignored.
const backdoor_ignore_local: set[string] &redef;
const backdoor_ignore_remote: set[string] &redef;

# Indexed by the source (destination) address and the backdoor.
# Also indexed by the /24 and /16 versions of the source address.
# backdoor "*" means "all backdoors".
const backdoor_ignore_src_addrs: table[string, addr] of bool &redef &default=F;
const backdoor_ignore_dst_addrs: table[string, addr] of bool &redef &default=F;

const backdoor_standard_ports = {
	telnet, rlogin, 512/tcp, 514/tcp, ftp, ssh, smtp, 143/tcp,
	110/tcp, 6667/tcp,
} &redef;
const backdoor_annotate_standard_ports = T &redef;

const backdoor_ignore_hosts: set[addr] &redef;
const backdoor_ignore_src_nets: set[subnet] &redef;
const backdoor_ignore_dst_nets: set[subnet] &redef;

# Most backdoors are enabled by default, but a few are disabled by
# default (T below) because they generated too many false positives
# (or, for HTTP, too many uninteresting true positives).
const ftp_sig_disabled			= F &redef;
const gaobot_sig_disabled		= F &redef;
const gnutella_sig_disabled		= F &redef;
const http_proxy_sig_disabled		= T &redef;
const http_sig_disabled			= T &redef;
const irc_sig_disabled			= F &redef;
const kazaa_sig_disabled		= F &redef;
const napster_sig_disabled		= F &redef;
const rlogin_sig_1byte_disabled		= T &redef;
const rlogin_sig_disabled		= T &redef;
const root_backdoor_sig_disabled	= T &redef;
const smtp_sig_disabled			= F &redef;
	# Note, for the following there's a corresponding variable
	# interconn_ssh_len_disabled in interconn.bro.
const ssh_len_disabled			= T &redef;
const ssh_sig_disabled			= F &redef;
const telnet_sig_3byte_disabled		= T &redef;
const telnet_sig_disabled		= T &redef;

global ssh_len_conns: set[conn_id];
global rlogin_conns: table[conn_id] of rlogin_conn_info;
global root_backdoor_sig_conns: set[conn_id];

global did_sig_conns: table[conn_id] of set[string];

const BACKDOOR_UNKNOWN = 0;
const BACKDOOR_YES = 1;
const BACKDOOR_NO = 2;
const BACKDOOR_SIG_FOUND = 3;

global telnet_sig_conns: table[conn_id] of count;
global telnet_sig_3byte_conns: table[conn_id] of count;

global smtp_sig_conns: table[conn_id] of count;
global irc_sig_conns: table[conn_id] of count;
global gaobot_sig_conns: table[conn_id] of count;

const backdoor_log = open_log_file("backdoor") &redef;

function ignore_backdoor_conn(c: connection, bd: string): bool
	{
	local oa = c$id$orig_h;
	local ra = c$id$resp_h;
	local op = c$id$orig_p;
	local rp = c$id$resp_p;

	if ( backdoor_ignore_ports[bd, op] ||
	     backdoor_ignore_ports[bd, rp] ||

	     # Check port wildcards.
	     backdoor_ignore_ports[bd, 0/tcp] ||

	     (ra in local_nets && bd in backdoor_ignore_local) ||
	     (ra !in local_nets && bd in backdoor_ignore_remote) ||

	     backdoor_ignore_src_addrs[bd, oa] ||
	     backdoor_ignore_src_addrs[bd, mask_addr(oa, 16)] ||
	     backdoor_ignore_src_addrs[bd, mask_addr(oa, 24)] ||

	     backdoor_ignore_dst_addrs[bd, ra] ||
	     backdoor_ignore_dst_addrs[bd, mask_addr(ra, 16)] ||
	     backdoor_ignore_dst_addrs[bd, mask_addr(ra, 24)] )
		return T;

	if ( [oa, op] in backdoor_ignore_host_port_pairs ||
	     [ra, rp] in backdoor_ignore_host_port_pairs )
		return T;

	if ( bd != "*" )
		# Evaluate again, but for wildcarding the backdoor.
		return ignore_backdoor_conn(c, "*");
	else
		return F;
	}

function log_backdoor(c: connection, tag: string): bool
	{
	if ( ignore_backdoor_conn(c, tag) )
		return F;

	local id = c$id;

	if ( backdoor_annotate_standard_ports &&
	     (id$orig_p in backdoor_standard_ports ||
	      id$resp_p in backdoor_standard_ports) )
		append_addl(c, fmt("[%s]", tag));

	else if ( id$orig_h in backdoor_ignore_hosts ||
		  id$resp_h in backdoor_ignore_hosts ||
		  id$orig_h in backdoor_ignore_src_nets ||
		  id$resp_h in backdoor_ignore_dst_nets )
		return F;

	else
		{
		print backdoor_log, fmt("%.6f %s > %s %s",
			c$start_time,
			endpoint_id(id$orig_h, id$orig_p),
			endpoint_id(id$resp_h, id$resp_p),
			tag);

		NOTICE([$note=BackdoorFound, $msg=tag, $conn=c]);

		if ( dump_backdoor_packets )
			{
			mkdir("backdoor-packets");
			local fname = fmt("backdoor-packets/%s:%.2f",
						tag, current_time());
			dump_current_packet(fname);
			}

		if ( backdoor_demux_disabled ||
		     tag in backdoor_demux_skip_tags )
			{
			if ( active_connection(c$id) )
				skip_further_processing(c$id);
			}
		else
			demux_conn(id, tag, "orig", "resp");
		}

	return T;
	}

event new_connection(c: connection)
	{
	local id = c$id;

	if ( ! rlogin_sig_disabled || ! rlogin_sig_1byte_disabled )
		{
		local i: rlogin_conn_info;
		i$o_num_null = i$o_len = i$r_num_null = i$r_len = 0;

		rlogin_conns[id] = i;
		}
	}

event backdoor_remove_conn(c: connection)
	{
	local id = c$id;

	delete ssh_len_conns[id];
	delete telnet_sig_conns[id];
	delete telnet_sig_3byte_conns[id];
	delete rlogin_conns[id];
	delete root_backdoor_sig_conns[id];
	delete smtp_sig_conns[id];
	delete irc_sig_conns[id];
	delete gaobot_sig_conns[id];

	delete did_sig_conns[id];
	}

event root_backdoor_signature_found(c: connection)
	{
	if ( root_backdoor_sig_disabled ||
	     ignore_backdoor_conn(c, "root-bd-sig") )
		return;

	local id = c$id;

	# For root backdoors, don't ignore standard ports.  This is because
	# we shouldn't see such a backdoor even 23/tcp or 513/tcp!

	if ( id !in root_backdoor_sig_conns )
		{
		add root_backdoor_sig_conns[id];
		log_backdoor(c, "root-bd-sig");
		}
	}

function signature_found(c: connection, sig_disabled: bool, sig_name: string)
	{
	if ( sig_disabled )
		return;

	if ( ignore_backdoor_conn(c, sig_name) )
		return;

	if ( c$id !in did_sig_conns )
		did_sig_conns[c$id] = set();

	if ( sig_name !in did_sig_conns[c$id] )
		{
		add did_sig_conns[c$id][sig_name];
		log_backdoor(c, sig_name);
		}
	}

event ftp_signature_found(c: connection)
	{
	signature_found(c, ftp_sig_disabled, "ftp-sig");
	}

event napster_signature_found(c: connection)
	{
	signature_found(c, napster_sig_disabled, "napster-sig");
	}

event gnutella_signature_found(c: connection)
	{
	signature_found(c, gnutella_sig_disabled, "gnutella-sig");
	}

event kazaa_signature_found(c: connection)
	{
	signature_found(c, kazaa_sig_disabled, "kazaa-sig");
	}

event http_signature_found(c: connection)
	{
	signature_found(c, http_sig_disabled, "http-sig");
	}

event http_proxy_signature_found(c: connection)
	{
	signature_found(c, http_proxy_sig_disabled, "http-proxy-sig");
	}

event ssh_signature_found(c: connection, is_orig: bool)
	{
	signature_found(c, ssh_sig_disabled, "ssh-sig");
	}

event smtp_signature_found(c: connection)
	{
	signature_found(c, smtp_sig_disabled, "smtp-sig");
	}

event irc_signature_found(c: connection)
	{
	signature_found(c, irc_sig_disabled, "irc-sig");
	}

event gaobot_signature_found(c: connection)
	{
	signature_found(c, gaobot_sig_disabled, "gaobot-sig");
	}

event telnet_signature_found(c: connection, is_orig: bool, len: count)
	{
	local id = c$id;

	if ( ignore_backdoor_conn(c, "telnet-sig") )
		return;

	if ( ! telnet_sig_disabled && id !in telnet_sig_conns )
		telnet_sig_conns[id] = BACKDOOR_SIG_FOUND;

	if ( ! telnet_sig_3byte_disabled && len == 3 &&
	     id !in telnet_sig_3byte_conns )
		telnet_sig_3byte_conns[id] = BACKDOOR_SIG_FOUND;
	}

event rlogin_signature_found(c: connection, is_orig: bool,
			     num_null: count, len: count)
	{
	local id = c$id;

	if ( (rlogin_sig_disabled && rlogin_sig_1byte_disabled) ||
	     ignore_backdoor_conn(c, "rlogin-sig") )
		return;

	local ri = rlogin_conns[id];
	if ( is_orig && ri$o_num_null == 0 )
		ri$o_num_null = num_null;

	else if ( ! is_orig && ri$r_num_null == 0 )
		{
		ri$r_num_null = num_null;
		ri$r_len = len;
		}
	else
		return;

	if ( ri$o_num_null == 0 || ri$r_num_null == 0 )
		return;

	if ( ! rlogin_sig_1byte_disabled && ri$r_len == 1 )
		log_backdoor(c, "rlogin-sig-1byte");

	if ( ! rlogin_sig_disabled )
		log_backdoor(c, "rlogin-sig");
	}


function ssh_len_stats(c: connection, os: backdoor_endp_stats,
		       rs: backdoor_endp_stats) : bool
	{
	if ( ssh_len_disabled || c$id in ssh_len_conns )
		return F;

	if ( os$num_pkts == 0 || rs$num_pkts == 0 )
		return F;

	# xxx: only use ssh-len for partial connection

	local is_partial = os$is_partial || rs$is_partial;
	if ( ! is_partial )
		return F;

	local num_pkts = os$num_pkts + rs$num_pkts;

	if ( num_pkts < ssh_min_num_pkts )
		return F;

	local num_8k0_pkts = os$num_8k0_pkts + rs$num_8k0_pkts;
	local num_8k4_pkts = os$num_8k4_pkts + rs$num_8k4_pkts;

	local id = c$id;
	if ( num_8k0_pkts >= num_pkts * ssh_min_ssh_pkts_ratio )
		{
		add ssh_len_conns[id];
		log_backdoor(c, "ssh-len-v2.x");
		}

	else if ( num_8k4_pkts >= num_pkts * ssh_min_ssh_pkts_ratio )
		{
		add ssh_len_conns[id];
		log_backdoor(c, "ssh-len-v1.x");
		}

	return T;
	}

function telnet_stats(c: connection, os: backdoor_endp_stats,
		      rs: backdoor_endp_stats) : bool
	{
	local num_lines = os$num_lines + rs$num_lines;
	local num_normal_lines = os$num_normal_lines + rs$num_normal_lines;

	if ( num_lines < backdoor_min_num_lines ||
	     num_normal_lines < num_lines * backdoor_min_normal_line_ratio )
		return F;

	local num_bytes = os$num_bytes + rs$num_bytes;
	local num_7bit_ascii = os$num_7bit_ascii + rs$num_7bit_ascii;

	if ( num_bytes < backdoor_min_bytes ||
	     num_7bit_ascii < num_bytes * backdoor_min_7bit_ascii_ratio )
		return F;

	local id = c$id;

	if ( id in telnet_sig_conns &&
	     telnet_sig_conns[id] != BACKDOOR_YES )
		{
		telnet_sig_conns[id] = BACKDOOR_YES;
		log_backdoor(c, "telnet-sig");
		}

	if ( id in telnet_sig_3byte_conns &&
	     telnet_sig_3byte_conns[id] != BACKDOOR_YES )
		{
		telnet_sig_3byte_conns[id] = BACKDOOR_YES;
		log_backdoor(c, "telnet-sig-3byte");
		}

	return T;
	}

event backdoor_stats(c: connection,
			os: backdoor_endp_stats, rs: backdoor_endp_stats)
	{
	telnet_stats(c, os, rs);
	ssh_len_stats(c, os, rs);
	}
