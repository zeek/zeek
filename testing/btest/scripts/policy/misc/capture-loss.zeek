# @TEST-EXEC: zeek -b -r $TRACES/dns53.pcap %INPUT
# @TEST-EXEC: btest-diff capture_loss.log
# @TEST-EXEC: btest-diff notice.log

@load misc/capture-loss

module CaptureLoss;

event zeek_init()
	{
	event take_measurement(network_time(), 0, 0);
	}
