##! This script adds geographic location data to notices for the "remote"
##! host in a connection.  It does make the assumption that one of the 
##! addresses in a connection is "local" and one is "remote" which is 
##! probably a safe assumption to make in most cases.  If both addresses
##! are remote, it will use the $src address.

@load ../main
@load base/frameworks/notice
@load base/utils/site

module Notice;

export {
	redef enum Action += {
		## Indicates that the notice should have geodata added for the
		## "remote" host.  :bro:id:`Site::local_nets` must be defined
		## in order for this to work.
		ACTION_ADD_GEODATA
	};
	
	redef record Info += {
		## If libGeoIP support is built in, notices can have geographic
		## information attached to them.
		remote_location: geo_location  &log &optional;
	};
	
	## Notice types which should have the "remote" location looked up.
	## If GeoIP support is not built in, this does nothing.
	const lookup_location_types: set[Notice::Type] = {} &redef;
}

hook policy(n: Notice::Info) &priority=10
	{
	if ( n$note in Notice::lookup_location_types )
		add n$actions[ACTION_ADD_GEODATA];
	}

# This is handled at a high priority in case other notice handlers 
# want to use the data.
hook notice(n: Notice::Info) &priority=10
	{
	if ( ACTION_ADD_GEODATA in n$actions &&
	     |Site::local_nets| > 0 &&
	     ! n?$remote_location )
		{
		if ( n?$src && ! Site::is_local_addr(n$src) )
			n$remote_location = lookup_location(n$src);
		else if ( n?$dst && ! Site::is_local_addr(n$dst) )
			n$remote_location = lookup_location(n$dst);
		}
	}
