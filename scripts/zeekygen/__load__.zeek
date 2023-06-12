@load test-all-policy.zeek

# Scripts which are commented out in test-all-policy.zeek.
@load protocols/mqtt/__load__.zeek
@load protocols/ssl/decryption.zeek
@load frameworks/cluster/nodes-experimental/manager.zeek
@load frameworks/control/controllee.zeek
@load frameworks/control/controller.zeek
@load frameworks/management/agent/main.zeek
@load frameworks/management/controller/main.zeek
@load frameworks/management/node/__load__.zeek
@load frameworks/management/node/main.zeek
@load frameworks/files/extract-all-files.zeek
@load policy/misc/dump-events.zeek
@load policy/protocols/conn/speculative-service.zeek

@if ( have_spicy() )
@load frameworks/spicy/record-spicy-batch.zeek
@load frameworks/spicy/resource-usage.zeek
@endif

@load ./example.zeek

event zeek_init()
	{
	terminate();
	}
