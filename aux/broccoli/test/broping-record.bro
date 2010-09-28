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

redef Remote::destinations += {
	["broping"] = [$host = 127.0.0.1, $events = /ping/, $connect=F, $ssl=F]
};

type ping_data: record {
	seq: count;
	src_time: time;
};

type pong_data: record {
	seq: count;
	src_time: time;
	dst_time: time;
};

# global pdata: pong_data;

global ping: event(data: ping_data);
global pong: event(data: pong_data);

event ping(data: ping_data)
        {
	local pdata: pong_data;
	
	pdata$seq      = data$seq;
	pdata$src_time = data$src_time;
	pdata$dst_time = current_time();

        event pong(pdata);
        }

event pong(data: pong_data)
        {
        print ping_log, fmt("ping received, seq %d, %f at src, %f at dest, one-way: %f",
                            data$seq, data$src_time, data$dst_time, data$dst_time - data$src_time);
        }
