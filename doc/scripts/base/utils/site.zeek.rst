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
:zeek:id:`Site::private_address_space`: :zeek:type:`set` :zeek:attr:`&redef` A list of subnets that are considered private address space.
============================================================================ ======================================================================

Redefinable Options
###################
====================================================================================== =================================================================
:zeek:id:`Site::private_address_space_is_local`: :zeek:type:`bool` :zeek:attr:`&redef` Whether Zeek should automatically consider private address ranges
                                                                                       "local".
====================================================================================== =================================================================

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
   :source-code: base/utils/site.zeek 146 146

   :Type: :zeek:type:`table` [:zeek:type:`subnet`] of :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   If local network administrators are known and they have responsibility
   for defined address space, then a mapping can be defined here between
   networks for which they have responsibility and a set of email
   addresses.

.. zeek:id:: Site::local_nets
   :source-code: base/utils/site.zeek 124 124

   :Type: :zeek:type:`set` [:zeek:type:`subnet`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Networks that are considered "local".  Note that ZeekControl sets
   this automatically.

.. zeek:id:: Site::local_zones
   :source-code: base/utils/site.zeek 149 149

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   DNS zones that are considered "local".

.. zeek:id:: Site::neighbor_nets
   :source-code: base/utils/site.zeek 140 140

   :Type: :zeek:type:`set` [:zeek:type:`subnet`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Networks that are considered "neighbors".

.. zeek:id:: Site::neighbor_zones
   :source-code: base/utils/site.zeek 152 152

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   DNS zones that are considered "neighbors".

.. zeek:id:: Site::private_address_space
   :source-code: base/utils/site.zeek 18 18

   :Type: :zeek:type:`set` [:zeek:type:`subnet`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            64:ff9b:1::/48,
            198.18.0.0/15,
            fc00::/7,
            100.64.0.0/10,
            ::/128,
            2002:ffff:ffff::/48,
            ::1/128,
            fec0::/10,
            2002:cb00:7100::/40,
            2002:c633:6400::/40,
            240.0.0.0/4,
            2002:a00::/24,
            100::/64,
            255.255.255.255/32,
            192.0.0.0/24,
            0.0.0.0/8,
            239.0.0.0/8,
            2001:2::/48,
            172.16.0.0/12,
            2002:c000:200::/40,
            2002:f000::/20,
            2002:7f00::/24,
            2001::/23,
            2002:6440::/26,
            2002:c000::/40,
            10.0.0.0/8,
            127.0.0.0/8,
            224.0.0.0/24,
            192.0.2.0/24,
            192.168.0.0/16,
            2002:ac10::/28,
            2002:a9fe::/32,
            169.254.0.0/16,
            2002:c612::/31,
            2002::/24,
            fe80::/10,
            2001:db8::/32,
            2002:ef00::/24,
            203.0.113.0/24,
            2002:e000::/40,
            2002:c0a8::/32,
            198.51.100.0/24
         }


   A list of subnets that are considered private address space.
   
   By default, it has address blocks defined by IANA as not being
   routable over the Internet. Some address blocks are reserved for
   purposes inconsistent with the address architecture (such as
   5f00::/16), making them neither clearly private nor routable. We do
   not include such blocks in this list.
   
   See the `IPv4 Special-Purpose Address Registry <https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml>`_
   and the `IPv6 Special-Purpose Address Registry <https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml>`_

Redefinable Options
###################
.. zeek:id:: Site::private_address_space_is_local
   :source-code: base/utils/site.zeek 130 130

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Whether Zeek should automatically consider private address ranges
   "local". On by default, this setting ensures that the initial value
   of :zeek:id:`Site::private_address_space` as well as any later
   updates to it get copied over into :zeek:id:`Site::local_nets`.

State Variables
###############
.. zeek:id:: Site::local_nets_table
   :source-code: base/utils/site.zeek 137 137

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
   :source-code: base/utils/site.zeek 257 260

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`string`

   Function that returns a comma-separated list of email addresses
   that are considered administrators for the IP address provided as
   an argument.
   The function inspects :zeek:id:`Site::local_admins`.

.. zeek:id:: Site::is_local_addr
   :source-code: base/utils/site.zeek 194 197

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`bool`

   Function that returns true if an address corresponds to one of
   the local networks, false if not.
   The function inspects :zeek:id:`Site::local_nets`.

.. zeek:id:: Site::is_local_name
   :source-code: base/utils/site.zeek 209 212

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`bool`

   Function that returns true if a host name is within a local
   DNS zone.
   The function inspects :zeek:id:`Site::local_zones`.

.. zeek:id:: Site::is_neighbor_addr
   :source-code: base/utils/site.zeek 199 202

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`bool`

   Function that returns true if an address corresponds to one of
   the neighbor networks, false if not.
   The function inspects :zeek:id:`Site::neighbor_nets`.

.. zeek:id:: Site::is_neighbor_name
   :source-code: base/utils/site.zeek 214 217

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`bool`

   Function that returns true if a host name is within a neighbor
   DNS zone.
   The function inspects :zeek:id:`Site::neighbor_zones`.

.. zeek:id:: Site::is_private_addr
   :source-code: base/utils/site.zeek 204 207

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`bool`

   Function that returns true if an address corresponds to one of
   the private/unrouted networks, false if not.
   The function inspects :zeek:id:`Site::private_address_space`.


