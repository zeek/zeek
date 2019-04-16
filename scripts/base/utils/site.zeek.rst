:tocdepth: 3

base/utils/site.zeek
====================
.. bro:namespace:: Site

Definitions describing a site - which networks and DNS zones are "local"
and "neighbors", and servers running particular services.

:Namespace: Site
:Imports: :doc:`base/utils/patterns.zeek </scripts/base/utils/patterns.zeek>`

Summary
~~~~~~~
Runtime Options
###############
========================================================================= ======================================================================
:bro:id:`Site::local_admins`: :bro:type:`table` :bro:attr:`&redef`        If local network administrators are known and they have responsibility
                                                                          for defined address space, then a mapping can be defined here between
                                                                          networks for which they have responsibility and a set of email
                                                                          addresses.
:bro:id:`Site::local_nets`: :bro:type:`set` :bro:attr:`&redef`            Networks that are considered "local".
:bro:id:`Site::local_zones`: :bro:type:`set` :bro:attr:`&redef`           DNS zones that are considered "local".
:bro:id:`Site::neighbor_nets`: :bro:type:`set` :bro:attr:`&redef`         Networks that are considered "neighbors".
:bro:id:`Site::neighbor_zones`: :bro:type:`set` :bro:attr:`&redef`        DNS zones that are considered "neighbors".
:bro:id:`Site::private_address_space`: :bro:type:`set` :bro:attr:`&redef` Address space that is considered private and unrouted.
========================================================================= ======================================================================

State Variables
###############
=================================================== =====================================================================
:bro:id:`Site::local_nets_table`: :bro:type:`table` This is used for retrieving the subnet when using multiple entries in
                                                    :bro:id:`Site::local_nets`.
=================================================== =====================================================================

Functions
#########
====================================================== =================================================================
:bro:id:`Site::get_emails`: :bro:type:`function`       Function that returns a comma-separated list of email addresses
                                                       that are considered administrators for the IP address provided as
                                                       an argument.
:bro:id:`Site::is_local_addr`: :bro:type:`function`    Function that returns true if an address corresponds to one of
                                                       the local networks, false if not.
:bro:id:`Site::is_local_name`: :bro:type:`function`    Function that returns true if a host name is within a local
                                                       DNS zone.
:bro:id:`Site::is_neighbor_addr`: :bro:type:`function` Function that returns true if an address corresponds to one of
                                                       the neighbor networks, false if not.
:bro:id:`Site::is_neighbor_name`: :bro:type:`function` Function that returns true if a host name is within a neighbor
                                                       DNS zone.
:bro:id:`Site::is_private_addr`: :bro:type:`function`  Function that returns true if an address corresponds to one of
                                                       the private/unrouted networks, false if not.
====================================================== =================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Site::local_admins

   :Type: :bro:type:`table` [:bro:type:`subnet`] of :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   If local network administrators are known and they have responsibility
   for defined address space, then a mapping can be defined here between
   networks for which they have responsibility and a set of email
   addresses.

.. bro:id:: Site::local_nets

   :Type: :bro:type:`set` [:bro:type:`subnet`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Networks that are considered "local".  Note that BroControl sets
   this automatically.

.. bro:id:: Site::local_zones

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   DNS zones that are considered "local".

.. bro:id:: Site::neighbor_nets

   :Type: :bro:type:`set` [:bro:type:`subnet`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Networks that are considered "neighbors".

.. bro:id:: Site::neighbor_zones

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   DNS zones that are considered "neighbors".

.. bro:id:: Site::private_address_space

   :Type: :bro:type:`set` [:bro:type:`subnet`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         192.168.0.0/16,
         127.0.0.0/8,
         ::1/128,
         172.16.0.0/12,
         10.0.0.0/8,
         fe80::/10,
         100.64.0.0/10
      }

   Address space that is considered private and unrouted.
   By default it has RFC defined non-routable IPv4 address space.

State Variables
###############
.. bro:id:: Site::local_nets_table

   :Type: :bro:type:`table` [:bro:type:`subnet`] of :bro:type:`subnet`
   :Default: ``{}``

   This is used for retrieving the subnet when using multiple entries in
   :bro:id:`Site::local_nets`.  It's populated automatically from there.
   A membership query can be done with an
   :bro:type:`addr` and the table will yield the subnet it was found
   within.

Functions
#########
.. bro:id:: Site::get_emails

   :Type: :bro:type:`function` (a: :bro:type:`addr`) : :bro:type:`string`

   Function that returns a comma-separated list of email addresses
   that are considered administrators for the IP address provided as
   an argument.
   The function inspects :bro:id:`Site::local_admins`.

.. bro:id:: Site::is_local_addr

   :Type: :bro:type:`function` (a: :bro:type:`addr`) : :bro:type:`bool`

   Function that returns true if an address corresponds to one of
   the local networks, false if not.
   The function inspects :bro:id:`Site::local_nets`.

.. bro:id:: Site::is_local_name

   :Type: :bro:type:`function` (name: :bro:type:`string`) : :bro:type:`bool`

   Function that returns true if a host name is within a local
   DNS zone.
   The function inspects :bro:id:`Site::local_zones`.

.. bro:id:: Site::is_neighbor_addr

   :Type: :bro:type:`function` (a: :bro:type:`addr`) : :bro:type:`bool`

   Function that returns true if an address corresponds to one of
   the neighbor networks, false if not.
   The function inspects :bro:id:`Site::neighbor_nets`.

.. bro:id:: Site::is_neighbor_name

   :Type: :bro:type:`function` (name: :bro:type:`string`) : :bro:type:`bool`

   Function that returns true if a host name is within a neighbor
   DNS zone.
   The function inspects :bro:id:`Site::neighbor_zones`.

.. bro:id:: Site::is_private_addr

   :Type: :bro:type:`function` (a: :bro:type:`addr`) : :bro:type:`bool`

   Function that returns true if an address corresponds to one of
   the private/unrouted networks, false if not.
   The function inspects :bro:id:`Site::private_address_space`.


