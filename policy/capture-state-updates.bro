#! $Id: capture-events.bro 6 2004-04-30 00:31:26Z jason $
#
# Captures all operations on &synchronized variables to state-updates.bst.
#

event bro_init()
	{
	capture_state_updates("state-updates.bst");
	}
