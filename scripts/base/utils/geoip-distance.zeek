##! Functions to calculate distance between two locations, based on GeoIP data.

## Returns the distance between two IP addresses using the haversine formula,
## based on GeoIP database locations.  Requires Zeek to be built with GeoIP.
##
## a1: First IP address.
##
## a2: Second IP address.
##
## Returns: The distance between *a1* and *a2* in miles, or -1.0 if GeoIP data
##          is not available for either of the IP addresses.
##
## .. zeek:see:: haversine_distance lookup_location
function haversine_distance_ip(a1: addr, a2: addr): double
	{
	local loc1 = lookup_location(a1);
	local loc2 = lookup_location(a2);
	local miles: double;

	if ( loc1?$latitude && loc1?$longitude && loc2?$latitude && loc2?$longitude )
		miles = haversine_distance(loc1$latitude, loc1$longitude, loc2$latitude, loc2$longitude);
	else
		miles = -1.0;

	return miles;
	}
