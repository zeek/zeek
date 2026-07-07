redef Log::default_rotation_postprocessor_cmd = "";
redef Log::enable_local_logging = T;
redef Cluster::manager_is_logger = F;
redef exit_only_after_terminate = T;

# A one-way ping to the recipient. The epoch increases every time a backpressure
# unpeering event disconnects the recipient. The counter never resets. The
# padding helps eat up space in the underlying TCP connection, speeding up the
# tests.
global ping: event(epoch: count, ctr: count, padding: string) &is_used;

# A ping from manager to the sender that the sender echoes back, to verify
# liveness of that peering. This should always keep chugging -- if not, it means
# the sender's I/O troubles propagate to the manager: global lockup.
global manager_ping: event(ctr: count) &is_used;

# Where to send the pings: from worker to proxy.
const ping_topic = "" &redef;

# Where the receiver should notify the sender of termination, after recovery.
const termination_topic = "" &redef;

# A file for ad-hoc tracing output, for troubleshooting.
global trace_file = open("trace.txt");

# Presence of this file un-wedges the receiver:
global unwedge_file = "../unwedge-receiver";

# The receiver sends this to manager and sender to shut them down, then
# terminates too.
event terminate_me() &is_used
	{
	print fmt("%s terminating", current_time());
	terminate();
	}
