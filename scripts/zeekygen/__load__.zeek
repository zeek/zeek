@load test-all-policy.zeek

# Scripts which are commented out in test-all-policy.zeek.
<<<<<<< HEAD
=======
@load frameworks/analyzer/deprecated-dpd-log.zeek
@load frameworks/conn_key/vlan_fivetuple.zeek

# Remove in v8.1: replaced by frameworks/analyzer/detect-protocols.zeek
@pragma push ignore-deprecations
@load frameworks/dpd/detect-protocols.zeek
@pragma pop ignore-deprecations

>>>>>>> cd934c460b (Merge remote-tracking branch 'origin/topic/christian/extensible-conntuples')
@load protocols/ssl/decryption.zeek
@load frameworks/cluster/nodes-experimental/manager.zeek
@load frameworks/control/controllee.zeek
@load frameworks/control/controller.zeek
@load frameworks/management/agent/main.zeek
@load frameworks/management/controller/main.zeek
@load frameworks/management/node/__load__.zeek
@load frameworks/management/node/main.zeek
@load frameworks/files/extract-all-files.zeek
@load frameworks/signatures/iso-9660.zeek
@load policy/misc/dump-events.zeek
@load policy/protocols/conn/speculative-service.zeek

@if ( have_spicy() )
# Loading this messes up documentation of some elements defined elsewhere.
# @load frameworks/spicy/record-spicy-batch.zeek
@load frameworks/spicy/resource-usage.zeek
@endif

@load ./example.zeek

event zeek_init() &priority=1000
	{
	# Disable events in modules that use zeek_init() to do stuff and may
	# fail when run under zeekygen. For the purpose of zeekygen, we could
	# probably disable all modules, too.
	disable_module_events("Control");
	disable_module_events("Management::Agent::Runtime");
	disable_module_events("Management::Controller::Runtime");
	disable_module_events("Management::Node");
	terminate();
	}
