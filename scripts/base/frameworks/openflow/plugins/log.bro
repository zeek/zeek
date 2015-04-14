##! OpenFlow module that outputs flow-modification commands
##! to a Bro log file.

module OpenFlow;

@load base/frameworks/openflow
@load base/frameworks/logging

export {
	redef enum Plugin += {
		LOG,
	};

	## Log controller constructor.
	##
	## dpid: OpenFlow switch datapath id.
	##
	## Returns: OpenFlow::Controller record
	global log_new: function(dpid: count): OpenFlow::Controller;

	redef record ControllerState += {
		## OpenFlow switch datapath id.
		log_dpid: count &optional;
	};

	## The record type which contains column fields of the OpenFlow log.
	type Info: record {
		## Network time
		ts: time &log;
		## OpenFlow switch datapath id
		dpid: count &log;
		## OpenFlow match fields
		match: ofp_match &log;
		## OpenFlow modify flow entry message
		flow_mod: ofp_flow_mod &log;
	};

	## Event that can be handled to access the :bro:type:`OpenFlow::Info`
	## record as it is sent on to the logging framework.
	global log_openflow: event(rec: Info);
}

event bro_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_openflow, $path="openflow"]);
	}

function log_flow_mod(state: ControllerState, match: ofp_match, flow_mod: OpenFlow::ofp_flow_mod): bool
	{
	Log::write(LOG, [$ts=network_time(), $dpid=state$log_dpid, $match=match, $flow_mod=flow_mod]);

	return T;
	}

function log_describe(state: ControllerState): string
	{
	return fmt("OpenFlog Log Plugin - DPID %d", state$log_dpid);
	}

function log_new(dpid: count): OpenFlow::Controller
	{
	return [$state=[$log_dpid=dpid, $_plugin=OpenFlow::LOG],
		$flow_mod=log_flow_mod, $flow_clear=ryu_flow_clear, $describe=log_describe];
	}
