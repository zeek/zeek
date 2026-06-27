redef Broker::peer_overflow_policy = "disconnect";
redef Log::default_rotation_postprocessor_cmd = "";
redef exit_only_after_terminate = T;

# A one-way ping to the recipient. The epoch increases every time a backpressure
# unpeering event disconnects the recipient. The counter never resets. The
# padding helps eat up space in the underlying TCP connection, speeding up the
# tests.
global ping: event(epoch: count, ctr: count, padding: string);

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
