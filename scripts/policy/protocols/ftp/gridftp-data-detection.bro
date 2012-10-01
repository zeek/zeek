##! A detection script for GridFTP data channels.  The heuristic used to
##! identify a GridFTP data channel relies on the fact that default
##! setting for GridFTP clients typically mutually authenticate the data
##! channel with SSL and negotiate a NULL bulk cipher (no encryption).
##! Connections with those attributes are then polled for two minutes
##! with decreasing frequency to check if the transfer sizes are large
##! enough to indicate a GridFTP data channel that would be undesireable
##! to analyze further (e.g. TCP reassembly no longer occurs).  A side
##! effect is that true connection sizes are not logged, but at the
##! benefit of saving CPU cycles that otherwise go to analyzing such
##! large (and hopefully benign) connections.

module GridFTP;

@load base/protocols/conn
@load base/protocols/ssl
@load base/frameworks/notice

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

	## Base amount of time between checking whether a GridFTP connection
	## has transferred more than :bro:see:`GridFTP::size_threshold` bytes.
	const poll_interval = 1sec &redef;

	## The amount of time the base :bro:see:`GridFTP::poll_interval` is
	## increased by each poll interval.  Can be used to make more frequent
	## checks at the start of a connection and gradually slow down.
	const poll_interval_increase = 1sec &redef;
}

redef enum Notice::Type += {
	Data_Channel
};

redef record SSL::Info += {
	## Indicates a client certificate was sent in the SSL handshake.
	saw_client_cert: bool &optional;
};

event x509_certificate(c: connection, is_orig: bool, cert: X509, chain_idx: count, chain_len: count, der_cert: string)
	{
	if ( is_orig && c?$ssl )
		c$ssl$saw_client_cert = T;
	}

function size_callback(c: connection, cnt: count): interval
	{
	if ( c$orig$size > size_threshold || c$resp$size > size_threshold )
		{
		local msg = fmt("GridFTP data channel over threshold %d bytes",
		                size_threshold);
		NOTICE([$note=Data_Channel, $msg=msg, $conn=c]);
		if ( skip_data )
			skip_further_processing(c$id);
		return -1sec;
		}

	if ( cnt >= max_poll_count ) return -1sec;

	return poll_interval + poll_interval_increase * cnt;
	}

event ssl_established(c: connection)
	{
	# By default GridFTP data channels do mutual authentication and
	# negotiate a cipher suite with a NULL bulk cipher.
	if ( c?$ssl && c$ssl?$saw_client_cert && c$ssl?$subject &&
	     c$ssl?$cipher && /WITH_NULL/ in c$ssl$cipher )
		{
		ConnPolling::watch(c, size_callback, 0, 0secs);
		}
	}
