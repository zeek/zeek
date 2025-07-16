##! Implements base functionality for QUIC analysis. Generates quic.log.

@load base/frameworks/notice/weird
@load base/protocols/conn/removal-hooks

@load ./consts

module QUIC;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp of first QUIC packet for this entry.
		ts:          time    &log;
		## Unique ID for the connection.
		uid:         string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:          conn_id &log;

		## QUIC version as found in the first INITIAL packet from
		## the client. This will often be "1" or "quicv2", but see
		## the :zeek:see:`QUIC::version_strings` table for details.
		version:     string  &log;

		## First Destination Connection ID used by client. This is
		## random and unpredictable, but used for packet protection
		## by client and server.
		client_initial_dcid: string  &log &optional;

		## Client's Source Connection ID from the first INITIAL packet.
		client_scid:         string  &log &optional;

		## Server chosen Connection ID usually from server's first
		## INITIAL packet. This is to be used by the client in
		## subsequent packets.
		server_scid:         string  &log &optional;

		## Server name extracted from SNI extension in ClientHello
		## packet if available.
		server_name: string  &log &optional;

		## First protocol extracted from ALPN extension in ClientHello
		## packet if available.
		client_protocol: string &log &optional;

		## QUIC history.
		##
		## Letters have the following meaning with client-sent
		## letters being capitalized:
		##
		## ======  ====================================================
		## Letter  Meaning
		## ======  ====================================================
		## I       INIT packet
		## H       HANDSHAKE packet
		## Z       0RTT packet
		## R       RETRY packet
		## C       CONNECTION_CLOSE packet
		## S       SSL Client/Server Hello
		## U       Unfamiliar QUIC version
		## ======  ====================================================
		history: string &log &default="";

		# Internal state for the history field.
		history_state: vector of string;

		# Internal state if this record has already been logged.
		logged: bool &default=F;
	};

	global log_quic: event(rec: Info);

	global log_policy: Log::PolicyHook;

	global finalize_quic: Conn::RemovalHook;

	## The maximum length of the history field.
	option max_history_length = 100;
}

redef record connection += {
	# XXX: We may have multiple QUIC connections with different
	#      Connection ID over the same UDP connection.
	quic: Info &optional;
};

# Faster to modify here than re-compiling .evt files.
const quic_ports = {
	443/udp, # HTTP3-over-QUIC
	853/udp, # DNS-over-QUIC
	784/udp, # DNS-over-QUIC early
};

function add_to_history(c: connection, is_orig: bool, what: string)
	{
	if ( |c$quic$history_state| == max_history_length )
		return;

	c$quic$history_state += is_orig ? to_upper(what[0]) : to_lower(what[0]);

	if ( |c$quic$history_state| == max_history_length )
		Reporter::conn_weird("QUIC_max_history_length_reached", c);
	}

function log_record(quic: Info)
	{
	quic$history = join_string_vec(quic$history_state, "");
	Log::write(LOG, quic);
	quic$logged = T;
	}

function set_session(c: connection, is_orig: bool, version: count, dcid: string, scid: string)
	{
	if ( ! c?$quic )
		{
		c$quic = Info(
			$ts=network_time(),
			$uid=c$uid,
			$id=c$id,
			$version=version_strings[version],
		);

		Conn::register_removal_hook(c, finalize_quic);
		}

	if ( is_orig && |dcid| > 0 && ! c$quic?$client_initial_dcid )
		c$quic$client_initial_dcid = bytestring_to_hexstr(dcid);

	if ( is_orig )
		c$quic$client_scid = bytestring_to_hexstr(scid);
	else
		c$quic$server_scid = bytestring_to_hexstr(scid);
	}

event QUIC::initial_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string)
	{
	set_session(c, is_orig, version, dcid, scid);
	add_to_history(c, is_orig, "INIT");
	}

event QUIC::handshake_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string)
	{
	set_session(c, is_orig, version, dcid, scid);
	add_to_history(c, is_orig, "HANDSHAKE");
	}

event QUIC::zero_rtt_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string)
	{
	set_session(c, is_orig, version, dcid, scid);
	add_to_history(c, is_orig, "ZeroRTT");
	}

# RETRY packets trigger a log entry and state reset.
event QUIC::retry_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string, retry_token: string, integrity_tag: string)
	{
	if ( ! c?$quic )
		set_session(c, is_orig, version, dcid, scid);

	add_to_history(c, is_orig, "RETRY");

	log_record(c$quic);

	delete c$quic;
	}

# If we couldn't handle a version, log it as a single record.
event QUIC::unhandled_version(c: connection, is_orig: bool, version: count, dcid: string, scid: string)
	{
	if ( ! c?$quic )
		set_session(c, is_orig, version, dcid, scid);

	add_to_history(c, is_orig, "UNHANDLED_VERSION");

	log_record(c$quic);

	delete c$quic;
	}

# Upon a connection_close_frame(), if any c$quic state is pending to be logged, do so
# now and prepare for a new entry.
event QUIC::connection_close_frame(c: connection, is_orig: bool, version: count, dcid: string, scid: string, error_code: count, reason_phrase: string)
	{
	if ( ! c?$quic )
		return;

	add_to_history(c, is_orig, "CONNECTION_CLOSE");

	log_record(c$quic);

	delete c$quic;
	}

event ssl_extension_server_name(c: connection, is_client: bool, names: string_vec) &priority=5
	{
	if ( is_client && c?$quic && |names| > 0 )
		c$quic$server_name = names[0];
	}

event ssl_extension_application_layer_protocol_negotiation(c: connection, is_client: bool, protocols: string_vec)
	{
	if ( c?$quic && is_client )
		{
		c$quic$client_protocol = protocols[0];
		if ( |protocols| > 1 )
			# Probably not overly weird, but the quic.log only
			# works with the first one in the hope to avoid
			# vector or concatenation.
			Reporter::conn_weird("QUIC_many_protocols", c, cat(protocols));
		}
	}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec)
	{
	if ( ! c?$quic )
		return;

	add_to_history(c, T, "SSL");
	}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=-5
	{
	if ( ! c?$quic )
		return;

	add_to_history(c, F, "SSL");
	}

hook finalize_quic(c: connection)
	{
	if ( ! c?$quic || c$quic$logged )
		return;

	log_record(c$quic);
	}

event zeek_init()
	{
	Log::create_stream(LOG, Log::Stream($columns=Info, $ev=log_quic, $path="quic", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_QUIC, quic_ports);
	}
