:tocdepth: 3

base/utils/geoip-distance.zeek
==============================

Functions to calculate distance between two locations, based on GeoIP data.


Summary
~~~~~~~
Functions
#########
======================================================= ==========================================================================
:zeek:id:`haversine_distance_ip`: :zeek:type:`function` Returns the distance between two IP addresses using the haversine formula,
                                                        based on GeoIP database locations.
======================================================= ==========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: haversine_distance_ip
   :source-code: base/utils/geoip-distance.zeek 14 26

   :Type: :zeek:type:`function` (a1: :zeek:type:`addr`, a2: :zeek:type:`addr`) : :zeek:type:`double`

   Returns the distance between two IP addresses using the haversine formula,
   based on GeoIP database locations.  Requires Zeek to be built with GeoIP.
   

   :param a1: First IP address.
   

   :param a2: Second IP address.
   

   :returns: The distance between *a1* and *a2* in miles, or -1.0 if GeoIP data
            is not available for either of the IP addresses.
   
   .. zeek:see:: haversine_distance lookup_location


