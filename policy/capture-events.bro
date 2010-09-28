#! $Id: capture-events.bro 4674 2007-07-30 22:00:43Z vern $
#
# Captures all events to events.bst.
#

event bro_init()
	{
	capture_events("events.bst");
	}
