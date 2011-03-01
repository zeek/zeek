# $Id: checkpoint.bro 6724 2009-06-07 09:23:03Z vern $
#
# Checkpoints Bro's persistent state at regular intervals and scans
# the state directory for external updates.

const state_rescan_interval = 15 secs &redef;
const state_checkpoint_interval = 15 min &redef;

# Services for which the internal connection state is stored.
const persistent_services = {
	21/tcp, # ftp
	22/tcp, # ssh
	23/tcp, # telnet
	513/tcp, # rlogin
} &redef;

# The first timer fires immediately. This flags lets us ignore it.
global state_ignore_first = T;

event state_checkpoint()
	{
	if ( state_ignore_first )
		state_ignore_first = F;

	else if ( ! bro_is_terminating() )
		checkpoint_state();

	if ( state_checkpoint_interval > 0 secs )
		schedule state_checkpoint_interval { state_checkpoint() };
	}

event state_rescan()
	{
	rescan_state();

	if ( state_rescan_interval > 0 secs )
		schedule state_rescan_interval { state_rescan() };
	}

event bro_init()
	{
	if ( state_checkpoint_interval > 0 secs )
		schedule state_checkpoint_interval { state_checkpoint() };

	if ( state_rescan_interval > 0 secs )
		schedule state_rescan_interval { state_rescan() };
	}

event connection_established(c: connection)
	{
	# Buggy?
	# if ( c$id$resp_p in persistent_services )
	#	make_connection_persistent(c);
	}
