:tocdepth: 3

base/utils/geoip-distance.zeek
==============================

Functions to calculate distance between two locations, based on GeoIP data.


Summary
~~~~~~~
Functions
#########
===================================================== ==========================================================================
:bro:id:`haversine_distance_ip`: :bro:type:`function` Returns the distance between two IP addresses using the haversine formula,
                                                      based on GeoIP database locations.
===================================================== ==========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: haversine_distance_ip

   :Type: :bro:type:`function` (a1: :bro:type:`addr`, a2: :bro:type:`addr`) : :bro:type:`double`

   Returns the distance between two IP addresses using the haversine formula,
   based on GeoIP database locations.  Requires Bro to be built with GeoIP.
   

   :a1: First IP address.
   

   :a2: Second IP address.
   

   :returns: The distance between *a1* and *a2* in miles, or -1.0 if GeoIP data
            is not available for either of the IP addresses.
   
   .. bro:see:: haversine_distance lookup_location


