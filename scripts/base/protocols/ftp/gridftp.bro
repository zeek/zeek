##! A detection script for GridFTP data and control channels.
##!
##! GridFTP control channels are identified by FTP control channels
##! that successfully negotiate the GSSAPI method of an AUTH request
##! and for which the exchange involved an encoded TLS/SSL handshake,
##! indicating the GSI mechanism for GSSAPI was used.  This analysis
##! is all supported internally, this script simply adds the "gridftp"
##! label to the *service* field of the control channel's
##! :bro:type:`connection` record.
##!
##! GridFTP data channels are identified by a heuristic that relies on
##! the fact that default settings for GridFTP clients typically
##! mutually authenticate the data channel with TLS/SSL and negotiate a
##! NULL bulk cipher (no encryption).  Connections with those
##! attributes are then polled for two minutes with decreasing frequency
##! to check if the transfer sizes are large enough to indicate a
##! GridFTP data channel that would be undesirable to analyze further
##! (e.g. stop TCP reassembly).  A side effect is that true connection
##! sizes are not logged, but at the benefit of saving CPU cycles that
##! would otherwise go to analyzing the large (and likely benign) connections.

@load ./info
@load ./main
@load base/protocols/conn
@load base/protocols/ssl
@load base/frameworks/notice

module GridFTP;

export {
	## Number of bytes transferred before guessing a connection is a
	## GridFTP data channel.
	const size_threshold = 1073741824 &redef;

	## Max number of times to check whether a connection's size exceeds the
	## :bro:see:`GridFTP::size_threshold`.
	const max_poll_count = 15 &redef;

	## Whether to skip further processing of the GridFTP data channel once
	## detected, which may help performance.
	const skip_data = T &redef;

	## Base amount of time between checking whether a GridFTP data connection
	## has transferred more than :bro:see:`GridFTP::size_threshold` bytes.
	const poll_interval = 1sec &redef;

	## The amount of time the base :bro:see:`GridFTP::poll_interval` is
	## increased by each poll interval.  Can be used to make more frequent
	## checks at the start of a connection and gradually slow down.
	const poll_interval_increase = 1sec &redef;

	## Raised when a GridFTP data channel is detected.
	##
	## c: The connection pertaining to the GridFTP data channel.
	global data_channel_detected: event(c: connection);

	## The initial criteria used to determine whether to start polling
	## the connection for the :bro:see:`GridFTP::size_threshold` to have
	## been exceeded.  This is called in a :bro:see:`ssl_established` event
	## handler and by default looks for both a client and server certificate
	## and for a NULL bulk cipher.  One way in which this function could be
	## redefined is to make it also consider client/server certificate
	## issuer subjects.
	##
	## c: The connection which may possibly be a GridFTP data channel.
	##
	## Returns: true if the connection should be further polled for an
	##          exceeded :bro:see:`GridFTP::size_threshold`, else false.
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

function size_callback(c: connection, cnt: count): interval
	{
	if ( c$orig$size > size_threshold || c$resp$size > size_threshold )
		{
		add c$service["gridftp-data"];
		event GridFTP::data_channel_detected(c);

		if ( skip_data )
			skip_further_processing(c$id);

		return -1sec;
		}

	if ( cnt >= max_poll_count )
		return -1sec;

	return poll_interval + poll_interval_increase * cnt;
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
	return ( c?$ssl && c$ssl?$client_subject && c$ssl?$subject &&
	         c$ssl?$cipher && /WITH_NULL/ in c$ssl$cipher );
	}

event ssl_established(c: connection) &priority=-3
	{
	# By default GridFTP data channels do mutual authentication and
	# negotiate a cipher suite with a NULL bulk cipher.
	if ( data_channel_initial_criteria(c) )
		ConnPolling::watch(c, size_callback, 0, 0secs);
	}
