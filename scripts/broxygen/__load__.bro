@load test-all-policy.bro

# Scripts which are commented out in test-all-policy.bro.
@load protocols/ssl/notary.bro
@load frameworks/communication/listen.bro
@load frameworks/control/controllee.bro
@load frameworks/control/controller.bro
@load policy/misc/dump-events.bro

@load ./example.bro

event bro_init()
	{
	terminate();
	}
