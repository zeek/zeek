# $Id: dhcp.bro 4054 2007-08-14 21:45:58Z pclin $

@load dpd
@load weird

module DHCP;

export {
	# Set to false to disable printing to dhcp.log.
	const logging = T &redef;
}

# Type of states in DHCP client.  See Figure 5 in RFC 2131.
# Each state name is prefixed with DHCP_ to avoid name conflicts.
type dhcp_state: enum {

	DHCP_INIT_REBOOT,
	DHCP_INIT,
	DHCP_SELECTING,
	DHCP_REQUESTING,
	DHCP_REBINDING,
	DHCP_BOUND,
	DHCP_RENEWING,
	DHCP_REBOOTING,

	# This state is not in Figure 5.  Client has been externally configured.
	DHCP_INFORM,
};

global dhcp_log: file;

# Source port 68: client -> server; source port 67: server -> client.
global dhcp_ports: set[port] = { 67/udp, 68/udp } &redef;

redef dpd_config += { [ANALYZER_DHCP_BINPAC] = [$ports = dhcp_ports] };

# Default handling for peculiarities in DHCP analysis.
redef Weird::weird_action += {
	["DHCP_no_type_option"] = Weird::WEIRD_FILE,
	["DHCP_wrong_op_type"] = Weird::WEIRD_FILE,
	["DHCP_wrong_msg_type"] = Weird::WEIRD_FILE,
};

# Types of DHCP messages, identified from the 'options' field.  See RFC 1533.
global dhcp_msgtype_name: table[count] of string = {
	[1] = "DHCP_DISCOVER",
	[2] = "DHCP_OFFER",
	[3] = "DHCP_REQUEST",
	[4] = "DHCP_DECLINE",
	[5] = "DHCP_ACK",
	[6] = "DHCP_NAK",
	[7] = "DHCP_RELEASE",
	[8] = "DHCP_INFORM",
};

# Type of DHCP client state, inferred from the messages.  See RFC 2131, fig 5.
global dhcp_state_name: table[dhcp_state] of string = {
	[DHCP_INIT_REBOOT] = "INIT-REBOOT",
	[DHCP_INIT]	   = "INIT",
	[DHCP_SELECTING]   = "SELECTING",
	[DHCP_REQUESTING]  = "REQUESTING",
	[DHCP_REBINDING]   = "REBINDING",
	[DHCP_BOUND]	   = "BOUND",
	[DHCP_RENEWING]    = "RENEWING",
	[DHCP_REBOOTING]   = "REBOOTING",
	[DHCP_INFORM]	   = "INFORM",
};

type dhcp_session_info: record {
	state: dhcp_state;	# the state of a DHCP client
	seq: count;		# sequence of session in the trace
	lease: interval;	# lease time of an IP address
	h_addr: string;		# hardware/MAC address of the client
};

# Track the DHCP session info of each client, indexed by the transaction ID.
global dhcp_session: table[count] of dhcp_session_info
	&default = record($state = DHCP_INIT_REBOOT, $seq = 0, $lease = 0 sec,
				$h_addr = "")
	&write_expire = 5 min
;

# We need the following table to track some DHCPINFORM messages since they
# use xid = 0 (I do not know why), starting from the second pair of INFORM
# and ACK.  Since the client address is ready before DHCPINFORM, we can use
# it as the index to find its corresponding xid.
global session_xid: table[addr] of count &read_expire = 30 sec;

# Count how many DHCP sessions have been detected, for use in dhcp_session_seq.
global pkt_cnt: count = 0;
global session_cnt: count = 0;

# Record the address of client that sends a DHCPINFORM message with xid = 0.
global recent_client: addr;

global BROADCAST_ADDR = 255.255.255.255;
global NULL_ADDR = 0.0.0.0;

# Used to detect if an ACK is duplicated.  They are used only in dhcp_ack().
# We put them here since Bro scripts lacks the equivalent of "static" variables.
global ack_from: addr;
global duplicated_ack: bool;


function warning_wrong_state(msg_type: count): string
	{
	return fmt("%s not sent in a correct state.",
			dhcp_msgtype_name[msg_type]);
	}

function dhcp_message(c: connection, seq: count, show_conn: bool): string
	{
	local conn_info = fmt("%.06f #%d", network_time(), seq);
	if ( show_conn )
		return fmt("%s %s > %s", conn_info,
				endpoint_id(c$id$orig_h, c$id$orig_p),
				endpoint_id(c$id$resp_h, c$id$resp_p));

	return conn_info;
	}

function new_dhcp_session(xid: count, state: dhcp_state, h_addr: string)
: dhcp_session_info
	{
	local session: dhcp_session_info;
	session$state = state;
	session$seq = ++session_cnt;
	session$lease = 0 sec;
	session$h_addr = h_addr;

	dhcp_session[xid] = session;

	return session;
	}


event bro_init()
	{
	if ( logging )
		dhcp_log = open_log_file("dhcp");
	}

event dhcp_discover(c: connection, msg: dhcp_msg, req_addr: addr)
	{
	local old_session = T;

	if ( msg$xid !in dhcp_session )
		{
		local session =
			new_dhcp_session(msg$xid, DHCP_SELECTING, msg$h_addr);
		old_session = F;
		}

	if ( logging )
		{
		if ( old_session &&
		     dhcp_session[msg$xid]$state == DHCP_SELECTING )
			print dhcp_log, fmt("%s DISCOVER (duplicated)",
				dhcp_message(c, dhcp_session[msg$xid]$seq, F));
		else
			print dhcp_log,
				fmt("%s DISCOVER (xid = %x, client state = %s)",
					dhcp_message(c, dhcp_session[msg$xid]$seq, T),
					msg$xid, dhcp_state_name[dhcp_session[msg$xid]$state]);
		}
	}

event dhcp_offer(c: connection, msg: dhcp_msg, mask: addr,
		router: dhcp_router_list, lease: interval, serv_addr: addr)
	{
	local standalone = msg$xid !in dhcp_session;
	local err_state =
		standalone && dhcp_session[msg$xid]$state != DHCP_SELECTING;

	if ( logging )
		{
		# Note that no OFFER messages are considered duplicated,
		# since they may come from multiple DHCP servers in a session.
		if ( standalone )
			print dhcp_log, fmt("%s OFFER (standalone)",
				dhcp_message(c, ++session_cnt, T));

		else if ( err_state )
			print dhcp_log, fmt("%s OFFER (in error state %s)",
				dhcp_message(c, dhcp_session[msg$xid]$seq, T),
				dhcp_state_name[dhcp_session[msg$xid]$state]);

		else
			print dhcp_log, fmt("%s OFFER (client state = %s)",
				dhcp_message(c, dhcp_session[msg$xid]$seq, T),
					dhcp_state_name[DHCP_SELECTING]);
		}
	}

event dhcp_request(c: connection, msg: dhcp_msg,
			req_addr: addr, serv_addr: addr)
	{
	local log_info: string;

	if ( msg$xid in dhcp_session )
		{
		if ( ! logging )
			return;

		local state = dhcp_session[msg$xid]$state;

		if ( state == DHCP_REBOOTING )
			recent_client = req_addr;
		else
			recent_client = c$id$orig_h;

		session_xid[recent_client] = msg$xid;

		if ( state == DHCP_RENEWING || state == DHCP_REBINDING ||
		     state == DHCP_REQUESTING || state == DHCP_REBOOTING )
			print dhcp_log, fmt("%s REQUEST (duplicated)",
				dhcp_message(c, dhcp_session[msg$xid]$seq, F));
		else
			{
			log_info = dhcp_message(c, dhcp_session[msg$xid]$seq, T);
			print dhcp_log, fmt("%s REQUEST (in error state %s)",
						log_info,
						dhcp_state_name[dhcp_session[msg$xid]$state]);
			}
		}
	else
		{
		local d_state = DHCP_REBOOTING;

		if ( c$id$resp_h != BROADCAST_ADDR )
			d_state = DHCP_RENEWING;
		else if ( msg$ciaddr != NULL_ADDR )
			d_state = DHCP_REBINDING;
		else if ( serv_addr != NULL_ADDR )
			d_state = DHCP_REQUESTING;

		local session = new_dhcp_session(msg$xid, d_state, msg$h_addr);

		if ( session$state == DHCP_REBOOTING )
			recent_client = req_addr;
		else
			recent_client = c$id$orig_h;

		session_xid[recent_client] = msg$xid;

		if ( logging )
			{
			log_info = dhcp_message(c, session$seq, T);
			if ( req_addr != NULL_ADDR )
				log_info = fmt("%s REQUEST %As",
						log_info, req_addr);
			else
				log_info = fmt("%s REQUEST", log_info);

			print dhcp_log, fmt("%s (xid = %x, client state = %s)",
						log_info, msg$xid,
						dhcp_state_name[session$state]);
			}
		}
	}

event dhcp_decline(c: connection, msg: dhcp_msg)
	{
	local old_session = msg$xid in dhcp_session;
	local err_state = F;

	if ( old_session )
		{
		if ( dhcp_session[msg$xid]$state == DHCP_REQUESTING )
			dhcp_session[msg$xid]$state = DHCP_INIT;
		else
			err_state = T;
		}
	else
		new_dhcp_session(msg$xid, DHCP_INIT, "");

	if ( ! logging )
		return;

	if ( old_session )
		{
		if ( err_state )
			print dhcp_log, fmt("%s DECLINE (in error state %s)",
				dhcp_message(c, dhcp_session[msg$xid]$seq, T),
				dhcp_state_name[dhcp_session[msg$xid]$state]);
		else
			print dhcp_log, fmt("%s DECLINE (duplicated)",
				dhcp_message(c, dhcp_session[msg$xid]$seq, F));
		}
	else
		print dhcp_log, fmt("%s DECLINE (xid = %x)",
			dhcp_message(c, ++session_cnt, T), msg$xid);
	}

event dhcp_ack(c: connection, msg: dhcp_msg, mask: addr,
		router: dhcp_router_list, lease: interval, serv_addr: addr)
	{
	local log_info: string;

	if ( msg$xid == 0 )
		{ # An ACK for a DHCPINFORM message with xid = 0.
		local xid =
			c$id$orig_h in session_xid ?
				# An ACK to the client.
				session_xid[c$id$orig_h]
			:
				# Assume ACK from a relay agent to the server.
				session_xid[recent_client];

		local seq: count;

		if ( xid > 0 )
			{
			duplicated_ack = dhcp_session[xid]$state != DHCP_INFORM;
			dhcp_session[xid]$state = DHCP_BOUND;
			seq = dhcp_session[xid]$seq;
			}
		else
			{
			# This is a weird situation.  We arbitrarily set
			# duplicated_ack to false to have more information
			# shown.
			duplicated_ack = F;
			seq = session_cnt;
			}

		if ( ! logging )
			return;

		log_info = dhcp_message(c, seq, F);
		if ( c$id$orig_h in session_xid )
			{
			if ( duplicated_ack )
				print dhcp_log, fmt("%s ACK (duplicated)",
							log_info);
			else
				print dhcp_log,
					fmt("%s ACK (client state = %s)",
						log_info,
						dhcp_state_name[DHCP_BOUND]);
			}
		else
			print dhcp_log,
				fmt("%s ACK (relay agent at = %As)",
					log_info, c$id$orig_h);
		return;
		}

	if ( msg$xid in dhcp_session )
		{
		local last_state = dhcp_session[msg$xid]$state;
		local from_reboot_state = last_state == DHCP_REBOOTING;

		if ( last_state == DHCP_REQUESTING ||
		     last_state == DHCP_REBOOTING ||
		     last_state == DHCP_RENEWING ||
		     last_state == DHCP_REBINDING ||
		     last_state == DHCP_INFORM )
			{
			dhcp_session[msg$xid]$state = DHCP_BOUND;
			dhcp_session[msg$xid]$lease = lease;
			}

		if ( ! logging )
			return;

		if ( last_state == DHCP_BOUND )
			{
			log_info = dhcp_message(c, dhcp_session[msg$xid]$seq, F);
			if ( c$id$orig_h == ack_from )
				log_info = fmt("%s ACK (duplicated)",
						log_info);

			else
				# Not a duplicated ACK.
				log_info = fmt("%s ACK (relay agent at = %As)",
						log_info, c$id$orig_h);
			}
		else
			{
			ack_from = c$id$orig_h;

			# If in a reboot state, we had better
			# explicitly show the original address
			# and the destination address of ACK,
			# because the client initally has a
			# zero address.
			if ( from_reboot_state )
				log_info = dhcp_message(c, dhcp_session[msg$xid]$seq, T);
			else
				log_info = dhcp_message(c, dhcp_session[msg$xid]$seq, F);

			if ( last_state != DHCP_INFORM &&
			     lease > 0 sec )
				log_info = fmt("%s ACK (lease time = %s, ",
						log_info, lease);
			else
				log_info = fmt("%s ACK (", log_info);

			log_info = fmt("%sclient state = %s)",
					log_info,
					dhcp_state_name[dhcp_session[msg$xid]$state]);
			}

		print dhcp_log, log_info;
		}

	else if ( logging )
		print dhcp_log, fmt("%s ACK (standalone)",
					dhcp_message(c, ++session_cnt, T));
	}

event dhcp_nak(c: connection, msg: dhcp_msg)
	{
	if ( msg$xid in dhcp_session )
		{
		local last_state = dhcp_session[msg$xid]$state;

		if ( last_state == DHCP_REQUESTING ||
		     last_state == DHCP_REBOOTING ||
		     last_state == DHCP_RENEWING ||
		     last_state == DHCP_REBINDING )
			dhcp_session[msg$xid]$state = DHCP_INIT;

		if ( logging )
			print dhcp_log, fmt("%s NAK (client state = %s)",
				dhcp_message(c, dhcp_session[msg$xid]$seq, F),
				dhcp_state_name[dhcp_session[msg$xid]$state]);
		}

	else if ( logging )
		print dhcp_log, fmt("%s NAK (standalone)",
			dhcp_message(c, ++session_cnt, T));
	}

event dhcp_release(c: connection, msg: dhcp_msg)
	{
	local old_session = msg$xid in dhcp_session;

	if ( ! old_session )
		# We assume the client goes back to DHCP_INIT
		# because the RFC does not specify which state to go to.
		new_dhcp_session(msg$xid, DHCP_INIT, "");

	if ( ! logging )
		return;

	if ( old_session )
		{
		if ( dhcp_session[msg$xid]$state == DHCP_INIT )
			print dhcp_log, fmt("%s RELEASE (duplicated)",
				dhcp_message(c, dhcp_session[msg$xid]$seq, F));
		else
			print dhcp_log, fmt("%s RELEASE, (client state = %s)",
				dhcp_message(c, dhcp_session[msg$xid]$seq, F),
				dhcp_state_name[dhcp_session[msg$xid]$state]);
		}
	else
		print dhcp_log, fmt("%s RELEASE (xid = %x, IP addr = %As)",
			dhcp_message(c, session_cnt, T), msg$xid, c$id$orig_h);
	}

event dhcp_inform(c: connection, msg: dhcp_msg)
	{
	recent_client = c$id$orig_h;

	if ( msg$xid == 0 )
		{
		# Oops! Try to associate message with transaction ID 0 with
		# a previous session.
		local xid: count;
		local seq: count;

		if ( c$id$orig_h in session_xid )
			{
			xid = session_xid[c$id$orig_h];
			dhcp_session[xid]$state = DHCP_INFORM;
			seq = dhcp_session[xid]$seq;
			}
		else
			{
			# Weird: xid = 0 and no previous INFORM-ACK dialog.
			xid = 0;
			seq = ++session_cnt;

			# Just record that a INFORM message has appeared,
			# although the xid is not useful.
			session_xid[c$id$orig_h] = 0;
			}

		if ( logging )
			print dhcp_log,
				fmt("%s INFORM (xid = %x, client state = %s)",
					dhcp_message(c, seq, T),
					xid, dhcp_state_name[DHCP_INFORM]);
		return;
		}

	if ( msg$xid in dhcp_session )
		{
		if ( logging )
			if ( dhcp_session[msg$xid]$state == DHCP_INFORM )
				print dhcp_log, fmt("%s INFORM (duplicated)",
					dhcp_message(c, dhcp_session[msg$xid]$seq, F));
			else	{
				print dhcp_log,
					fmt("%s INFORM (duplicated, client state = %s)",
						dhcp_message(c, dhcp_session[msg$xid]$seq, F),
						dhcp_state_name[dhcp_session[msg$xid]$state]);
				}

		return;
		}

	local session = new_dhcp_session(msg$xid, DHCP_INFORM, msg$h_addr);

	# Associate this transaction ID with the host so we can identify
	# subsequent pairs of INFORM/ACK if client uses xid=0.
	session_xid[c$id$orig_h] = msg$xid;

	if ( logging )
		print dhcp_log, fmt("%s INFORM (xid = %x, client state = %s)",
				dhcp_message(c, session$seq, T),
				msg$xid, dhcp_state_name[session$state]);
	}
