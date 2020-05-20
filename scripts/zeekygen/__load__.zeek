@load test-all-policy.zeek

# Scripts which are commented out in test-all-policy.zeek.
@load protocols/ssl/notary.zeek
@load frameworks/control/controllee.zeek
@load frameworks/control/controller.zeek
@load frameworks/files/extract-all-files.zeek
@load policy/misc/dump-events.zeek
@load policy/protocols/conn/speculative-service.zeek

@load ./example.zeek

event zeek_init()
	{
	terminate();
	}
