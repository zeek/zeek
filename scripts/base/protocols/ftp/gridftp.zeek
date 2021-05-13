##! A detection script for GridFTP data and control channels.
##!
##! GridFTP control channels are identified by FTP control channels
##! that successfully negotiate the GSSAPI method of an AUTH request
##! and for which the exchange involved an encoded TLS/SSL handshake,
##! indicating the GSI mechanism for GSSAPI was used.  This analysis
##! is all supported internally, this script simply adds the "gridftp"
##! label to the *service* field of the control channel's
##! :zeek:type:`connection` record.
##!
##! GridFTP data channels are identified by a heuristic that relies on
##! the fact that default settings for GridFTP clients typically
##! mutually authenticate the data channel with TLS/SSL and negotiate a
##! NULL bulk cipher (no encryption). Connections with those attributes
##! are marked as GridFTP if the data transfer within the first two minutes
##! is big enough to indicate a GripFTP data channel that would be
##! undesirable to analyze further (e.g. stop TCP reassembly).  A side
##! effect is that true connection sizes are not logged, but at the benefit
##! of saving CPU cycles that would otherwise go to analyzing the large
##! (and likely benign) connections.

@load ./info
@load ./main
@load base/protocols/conn
@load base/protocols/ssl
@load base/frameworks/notice

module GridFTP;

export {
	## Number of bytes transferred before guessing a connection is a
	## GridFTP data channel.
	option size_threshold = 1073741824;

	## Time during which we check whether a connection's size exceeds the
	## :zeek:see:`GridFTP::size_threshold`.
	option max_time = 2 min;

	## Whether to skip further processing of the GridFTP data channel once
	## detected, which may help performance.
	option skip_data = T;

	## Raised when a GridFTP data channel is detected.
	##
	## c: The connection pertaining to the GridFTP data channel.
	global data_channel_detected: event(c: connection);

	## The initial criteria used to determine whether to start polling
	## the connection for the :zeek:see:`GridFTP::size_threshold` to have
	## been exceeded.  This is called in a :zeek:see:`ssl_established` event
	## handler and by default looks for both a client and server certificate
	## and for a NULL bulk cipher.  One way in which this function could be
	## redefined is to make it also consider client/server certificate
	## issuer subjects.
	##
	## c: The connection which may possibly be a GridFTP data channel.
	##
	## Returns: true if the connection should be further polled for an
	##          exceeded :zeek:see:`GridFTP::size_threshold`, else false.
	const data_channel_initial_criteria: function(c: connection): bool &redef;
}

redef record FTP::Info += {
	last_auth_requested: string &optional;
};

event ftp_request(c: connection, command: string, arg: string) &priority=4
	{
	if ( command == "AUTH" && c?$ftp )
		c$ftp$last_auth_requested = arg;
	}

event ConnThreshold::bytes_threshold_crossed(c: connection, threshold: count, is_orig: bool)
	{
	if ( threshold < size_threshold || "gridftp-data" in c$service || c$duration > max_time )
		return;

	if ( ! data_channel_initial_criteria(c) )
		return;

	add c$service["gridftp-data"];
	event GridFTP::data_channel_detected(c);

	if ( skip_data )
		skip_further_processing(c$id);
	}

event gridftp_possibility_timeout(c: connection)
	{
	# only remove if we did not already detect it and the connection
	# is not yet at its end.
	if ( "gridftp-data" !in c$service && ! (c?$conn && c$conn?$service) )
		{
		ConnThreshold::delete_bytes_threshold(c, size_threshold, T);
		ConnThreshold::delete_bytes_threshold(c, size_threshold, F);
		}
	}

event ssl_established(c: connection) &priority=5
	{
	# If an FTP client requests AUTH GSSAPI and later an SSL handshake
	# finishes, it's likely a GridFTP control channel, so add service label.
	if ( c?$ftp && c$ftp?$last_auth_requested &&
	     /GSSAPI/ in c$ftp$last_auth_requested )
		add c$service["gridftp"];
	}

function data_channel_initial_criteria(c: connection): bool
	{
	return ( c?$ssl && |c$ssl$cert_chain| > 0 && |c$ssl$client_cert_chain| > 0 &&
	         c$ssl?$cipher && /WITH_NULL/ in c$ssl$cipher );
	}

event ssl_established(c: connection) &priority=-3
	{
	# By default GridFTP data channels do mutual authentication and
	# negotiate a cipher suite with a NULL bulk cipher.
	if ( data_channel_initial_criteria(c) )
		{
		ConnThreshold::set_bytes_threshold(c, size_threshold, T);
		ConnThreshold::set_bytes_threshold(c, size_threshold, F);
		schedule max_time { gridftp_possibility_timeout(c) };
		}
	}
