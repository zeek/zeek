:tocdepth: 3

base/utils/site.zeek
====================
.. zeek:namespace:: Site

Definitions describing a site - which networks and DNS zones are "local"
and "neighbors", and servers running particular services.

:Namespace: Site
:Imports: :doc:`base/utils/patterns.zeek </scripts/base/utils/patterns.zeek>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================ ======================================================================
:zeek:id:`Site::local_admins`: :zeek:type:`table` :zeek:attr:`&redef`        If local network administrators are known and they have responsibility
                                                                             for defined address space, then a mapping can be defined here between
                                                                             networks for which they have responsibility and a set of email
                                                                             addresses.
:zeek:id:`Site::local_nets`: :zeek:type:`set` :zeek:attr:`&redef`            Networks that are considered "local".
:zeek:id:`Site::local_zones`: :zeek:type:`set` :zeek:attr:`&redef`           DNS zones that are considered "local".
:zeek:id:`Site::neighbor_nets`: :zeek:type:`set` :zeek:attr:`&redef`         Networks that are considered "neighbors".
:zeek:id:`Site::neighbor_zones`: :zeek:type:`set` :zeek:attr:`&redef`        DNS zones that are considered "neighbors".
:zeek:id:`Site::private_address_space`: :zeek:type:`set` :zeek:attr:`&redef` Address space that is considered private and unrouted.
============================================================================ ======================================================================

State Variables
###############
===================================================== =====================================================================
:zeek:id:`Site::local_nets_table`: :zeek:type:`table` This is used for retrieving the subnet when using multiple entries in
                                                      :zeek:id:`Site::local_nets`.
===================================================== =====================================================================

Functions
#########
======================================================== =================================================================
:zeek:id:`Site::get_emails`: :zeek:type:`function`       Function that returns a comma-separated list of email addresses
                                                         that are considered administrators for the IP address provided as
                                                         an argument.
:zeek:id:`Site::is_local_addr`: :zeek:type:`function`    Function that returns true if an address corresponds to one of
                                                         the local networks, false if not.
:zeek:id:`Site::is_local_name`: :zeek:type:`function`    Function that returns true if a host name is within a local
                                                         DNS zone.
:zeek:id:`Site::is_neighbor_addr`: :zeek:type:`function` Function that returns true if an address corresponds to one of
                                                         the neighbor networks, false if not.
:zeek:id:`Site::is_neighbor_name`: :zeek:type:`function` Function that returns true if a host name is within a neighbor
                                                         DNS zone.
:zeek:id:`Site::is_private_addr`: :zeek:type:`function`  Function that returns true if an address corresponds to one of
                                                         the private/unrouted networks, false if not.
======================================================== =================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Site::local_admins

   :Type: :zeek:type:`table` [:zeek:type:`subnet`] of :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   If local network administrators are known and they have responsibility
   for defined address space, then a mapping can be defined here between
   networks for which they have responsibility and a set of email
   addresses.

.. zeek:id:: Site::local_nets

   :Type: :zeek:type:`set` [:zeek:type:`subnet`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Networks that are considered "local".  Note that ZeekControl sets
   this automatically.

.. zeek:id:: Site::local_zones

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   DNS zones that are considered "local".

.. zeek:id:: Site::neighbor_nets

   :Type: :zeek:type:`set` [:zeek:type:`subnet`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Networks that are considered "neighbors".

.. zeek:id:: Site::neighbor_zones

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   DNS zones that are considered "neighbors".

.. zeek:id:: Site::private_address_space

   :Type: :zeek:type:`set` [:zeek:type:`subnet`]
   :Attributes: :zeek:attr:`&redef`
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
.. zeek:id:: Site::local_nets_table

   :Type: :zeek:type:`table` [:zeek:type:`subnet`] of :zeek:type:`subnet`
   :Default: ``{}``

   This is used for retrieving the subnet when using multiple entries in
   :zeek:id:`Site::local_nets`.  It's populated automatically from there.
   A membership query can be done with an
   :zeek:type:`addr` and the table will yield the subnet it was found
   within.

Functions
#########
.. zeek:id:: Site::get_emails

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`string`

   Function that returns a comma-separated list of email addresses
   that are considered administrators for the IP address provided as
   an argument.
   The function inspects :zeek:id:`Site::local_admins`.

.. zeek:id:: Site::is_local_addr

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`bool`

   Function that returns true if an address corresponds to one of
   the local networks, false if not.
   The function inspects :zeek:id:`Site::local_nets`.

.. zeek:id:: Site::is_local_name

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`bool`

   Function that returns true if a host name is within a local
   DNS zone.
   The function inspects :zeek:id:`Site::local_zones`.

.. zeek:id:: Site::is_neighbor_addr

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`bool`

   Function that returns true if an address corresponds to one of
   the neighbor networks, false if not.
   The function inspects :zeek:id:`Site::neighbor_nets`.

.. zeek:id:: Site::is_neighbor_name

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`bool`

   Function that returns true if a host name is within a neighbor
   DNS zone.
   The function inspects :zeek:id:`Site::neighbor_zones`.

.. zeek:id:: Site::is_private_addr

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`bool`

   Function that returns true if an address corresponds to one of
   the private/unrouted networks, false if not.
   The function inspects :zeek:id:`Site::private_address_space`.


