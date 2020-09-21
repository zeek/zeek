##! OpenFlow plugin that outputs flow-modification commands
##! to a Zeek log file.

@load base/frameworks/openflow
@load base/frameworks/logging

module OpenFlow;

export {
	redef enum Plugin += {
		OFLOG,
	};

	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	## Log controller constructor.
	##
	## dpid: OpenFlow switch datapath id.
	##
	## success_event: If true, flow_mod_success is raised for each logged line.
	##
	## Returns: OpenFlow::Controller record.
	global log_new: function(dpid: count, success_event: bool &default=T): OpenFlow::Controller;

	redef record ControllerState += {
		## OpenFlow switch datapath id.
		log_dpid: count &optional;
		## Raise or do not raise success event.
		log_success_event: bool &optional;
	};

	## The record type which contains column fields of the OpenFlow log.
	type Info: record {
		## Network time.
		ts: time &log;
		## OpenFlow switch datapath id.
		dpid: count &log;
		## OpenFlow match fields.
		match: ofp_match &log;
		## OpenFlow modify flow entry message.
		flow_mod: ofp_flow_mod &log;
	};

	## Event that can be handled to access the :zeek:type:`OpenFlow::Info`
	## record as it is sent on to the logging framework.
	global log_openflow: event(rec: Info);
}

event zeek_init() &priority=5
	{
	Log::create_stream(OpenFlow::LOG, [$columns=Info, $ev=log_openflow, $path="openflow", $policy=log_policy]);
	}

function log_flow_mod(state: ControllerState, match: ofp_match, flow_mod: OpenFlow::ofp_flow_mod): bool
	{
	Log::write(OpenFlow::LOG, [$ts=network_time(), $dpid=state$log_dpid, $match=match, $flow_mod=flow_mod]);
	if ( state$log_success_event )
		event OpenFlow::flow_mod_success(state$_name, match, flow_mod);

	return T;
	}

function log_describe(state: ControllerState): string
	{
	return fmt("Log-%d", state$log_dpid);
	}

function log_new(dpid: count, success_event: bool &default=T): OpenFlow::Controller
	{
	local c = OpenFlow::Controller($state=OpenFlow::ControllerState($log_dpid=dpid, $log_success_event=success_event),
		$flow_mod=log_flow_mod, $describe=log_describe, $supports_flow_removed=F);

	register_controller(OpenFlow::OFLOG, cat(dpid), c);

	return c;
	}
