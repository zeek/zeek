# $Id: ntp.bro 4758 2007-08-10 06:49:23Z vern $

@load udp-common

redef capture_filters += { ["ntp"] = "udp port 123" };

module NTP;

export {
	const excessive_ntp_request = 48 &redef;
	const allow_excessive_ntp_requests: set[addr] &redef;
}

# DPM configuration.
global ntp_ports = { 123/udp } &redef;
redef dpd_config += { [ANALYZER_NTP] = [$ports = ntp_ports] };

const ntp_code: table[count] of string = {
	[0] = "unspec",
	[1] = "sym_act",
	[2] = "sym_psv",
	[3] = "client",
	[4] = "server",
	[5] = "bcast",
	[6] = "rsv1",
	[7] = "rsv2",
};

event ntp_message(u: connection, msg: ntp_msg, excess: string)
	{
	local id = u$id;

	if ( id !in udp_rep_count && id !in udp_req_count )
		{
		Hot::check_hot(u, Hot::CONN_ATTEMPTED);
		Scan::check_scan(u, F, F);
		}

	if ( msg$code == 4 )
		# "server"
		++udp_rep_count[id];
	else
		# anything else
		++udp_req_count[id];

	local n_excess = byte_len(excess);
	if ( n_excess > excessive_ntp_request &&
	     id$orig_h !in allow_excessive_ntp_requests )
		{
		append_addl_marker(u, fmt("%s", n_excess), ",");
		++u$hot;
		}
	}
