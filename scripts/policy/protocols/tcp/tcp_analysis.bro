@load base/protocols/tcp/tcp_retransmissions
@load base/protocols/tcp/tcp_reordering
@load base/protocols/tcp/tcp_deadconn
@load base/protocols/tcp/tcp_options
@load base/protocols/tcp/tcp_recovery
@load base/protocols/tcp/tcp_rtt
@load base/protocols/tcp/tcp_osfp

redef use_tcp_analyzer=T;

module TCP;
