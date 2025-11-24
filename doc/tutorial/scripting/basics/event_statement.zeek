# This is a brand new event
event my_custom_event(a_num: count) {
	print fmt("My custom event got %d!", a_num);
}

event zeek_init() {
	# 'event' can be used to immediately queue the event handler invocation.
	# You can even pass in values!
	event my_custom_event(5);
	# The event is now queued, so it will run eventually, but this print
	# will happen first. We are still in this event!
	print "This happens first!";

	# We cannot return any values from events, so this is invalid:
	# local x = event my_custom_event(10);
}
