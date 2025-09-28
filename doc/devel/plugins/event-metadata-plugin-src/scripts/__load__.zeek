module EventLatency;

redef enum EventMetadata::ID += {
	## Identifier for the absolute time at which Zeek published this event.
	WALLCLOCK_TIMESTAMP = 10001000,
};

event zeek_init()
	{
	assert EventMetadata::register(WALLCLOCK_TIMESTAMP, time);
	}
