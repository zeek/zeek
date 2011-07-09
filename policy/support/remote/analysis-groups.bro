##! This script gives the capability to selectively enable and disable event 
##! groups at runtime. No events will be raised for all memmbers of a disabled
##! event group.

@load support/remote

module Remote;

export {
	# By default, all event groups are enabled. We disable all groups in this table.
	const disabled_analysis_groups: set[string] &redef; # = { "ftp" }
}

# Set to remember all groups which were disabled by the last update().
global currently_disabled: set[string];

event configuration_update()
	{
	# Reenable those which are not to be disabled anymore.
	for ( g in currently_disabled )
		if ( g !in disabled_analysis_groups ) 
			enable_event_group(g);
	
	# Disable those which are not already.
	for ( g in disabled_analysis_groups )
		if ( g !in currently_disabled )
			disable_event_group(g);
	
	currently_disabled = copy(disabled_analysis_groups);
	}