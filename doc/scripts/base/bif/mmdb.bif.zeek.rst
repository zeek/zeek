:tocdepth: 3

base/bif/mmdb.bif.zeek
======================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
========================================================== ================================================================
:zeek:id:`lookup_autonomous_system`: :zeek:type:`function` Performs an lookup of AS number & organization of an IP address.
:zeek:id:`lookup_location`: :zeek:type:`function`          Performs a geo-lookup of an IP address.
:zeek:id:`mmdb_open_asn_db`: :zeek:type:`function`         Initializes MMDB for later use of lookup_autonomous_system.
:zeek:id:`mmdb_open_location_db`: :zeek:type:`function`    Initializes MMDB for later use of lookup_location.
========================================================== ================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: lookup_autonomous_system
   :source-code: base/bif/mmdb.bif.zeek 47 47

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`geo_autonomous_system`

   Performs an lookup of AS number & organization of an IP address.
   Requires Zeek to be built with ``libmaxminddb``.


   :param a: The IP address to lookup.


   :returns: A record with autonomous system number and organization that contains *a*.

   .. zeek:see:: lookup_location

.. zeek:id:: lookup_location
   :source-code: base/bif/mmdb.bif.zeek 36 36

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`geo_location`

   Performs a geo-lookup of an IP address.
   Requires Zeek to be built with ``libmaxminddb``.


   :param a: The IP address to lookup.


   :returns: A record with country, region, city, latitude, and longitude.

   .. zeek:see:: lookup_autonomous_system

.. zeek:id:: mmdb_open_asn_db
   :source-code: base/bif/mmdb.bif.zeek 25 25

   :Type: :zeek:type:`function` (f: :zeek:type:`string`) : :zeek:type:`bool`

   Initializes MMDB for later use of lookup_autonomous_system.
   Requires Zeek to be built with ``libmaxminddb``.


   :param f: The filename of the MaxMind ASN DB.


   :returns: A boolean indicating whether the db was successfully opened.

   .. zeek:see:: lookup_autonomous_system

.. zeek:id:: mmdb_open_location_db
   :source-code: base/bif/mmdb.bif.zeek 14 14

   :Type: :zeek:type:`function` (f: :zeek:type:`string`) : :zeek:type:`bool`

   Initializes MMDB for later use of lookup_location.
   Requires Zeek to be built with ``libmaxminddb``.


   :param f: The filename of the MaxMind City or Country DB.


   :returns: A boolean indicating whether the db was successfully opened.

   .. zeek:see:: lookup_autonomous_system


