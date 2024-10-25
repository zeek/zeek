# Helper scripts for test expecting XPUB/XSUB ports allocated by
# btest and configuring the ZeroMQ globals.
@load base/utils/numbers

@load frameworks/cluster/backend/zeromq
@load frameworks/cluster/backend/zeromq/connect

# The manager runs the ZeroMQ proxy thread.
redef Cluster::Backend::ZeroMQ::listen_xpub_endpoint = fmt("tcp://127.0.0.1:%s", extract_count(getenv("XPUB_PORT")));
redef Cluster::Backend::ZeroMQ::listen_xsub_endpoint = fmt("tcp://127.0.0.1:%s", extract_count(getenv("XSUB_PORT")));
redef Cluster::Backend::ZeroMQ::connect_xpub_endpoint = fmt("tcp://127.0.0.1:%s", extract_count(getenv("XSUB_PORT")));
redef Cluster::Backend::ZeroMQ::connect_xsub_endpoint = fmt("tcp://127.0.0.1:%s", extract_count(getenv("XPUB_PORT")));

global finish: event();
global ping: event(c: count, how: string);
global pong: event(c: count, how: string, from: string, from_how: string);
