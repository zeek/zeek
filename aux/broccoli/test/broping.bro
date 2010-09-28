# Depending on whether you want to use encryption or not,
# include "listen-clear" or "listen-ssl":
#
# @load listen-ssl
@load listen-clear

global ping_log = open_log_file("ping");

# Let's make sure we use the same port no matter whether we use encryption or not:
#
@ifdef (listen_port_clear)
redef listen_port_clear    = 47758/tcp;
@endif

# If we're using encrypted communication, redef the SSL port and hook in
# the necessary certificates:
#
@ifdef (listen_port_ssl)
redef listen_port_ssl      = 47758/tcp;
redef ssl_ca_certificate   = "<path>/ca_cert.pem";
redef ssl_private_key      = "<path>/bro.pem";
@endif

global ping: event(src_time: time, seq: count);
global pong: event(src_time: time, dst_time: time, seq: count);

redef Remote::destinations += {
	["broping"] = [$host = 127.0.0.1, $events = /ping/, $connect=F, $ssl=F]
};

event ping(src_time: time, seq: count)
        {
        event pong(src_time, current_time(), seq);
        }

event pong(src_time: time, dst_time: time, seq: count)
        {
        print ping_log, fmt("ping received, seq %d, %f at src, %f at dest, one-way: %f",
                            seq, src_time, dst_time, dst_time-src_time);
        }
