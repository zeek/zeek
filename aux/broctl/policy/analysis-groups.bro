# $Id: analysis-groups.bro 6813 2009-07-07 18:54:12Z robin $
#
# This script allows to selectively enable/disable event groups. No events will be
# raised for all memmbers of a disabled event group.

module AnalysisGroups;

export 
	{
	# By default, all event groups are enabled. We disable all groups in this table.
	const disabled_groups: set[string] &redef; # = { "ftp" }

	# When the table above gets modified during run-time, calling this function
	# will put the changes into effect.
	global update: function();
	}

# Set to remember all groups which were disabled by the last update().
global currently_disabled: set[string];

function update()
	{
	# Reenable those which are not to be disabled anymore.
	for ( g in currently_disabled )
		if ( g !in disabled_groups )
			enable_event_group(g);
	
	# Disable those which are not already.
	for ( g in disabled_groups )
		if ( g !in currently_disabled )
			disable_event_group(g);
	
	currently_disabled = copy(disabled_groups);
	}

event bro_init()
	{
	update();
	}







