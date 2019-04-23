:tocdepth: 3

base/frameworks/tunnels/main.zeek
=================================
.. zeek:namespace:: Tunnel

This script handles the tracking/logging of tunnels (e.g. Teredo,
AYIYA, or IP-in-IP such as 6to4 where "IP" is either IPv4 or IPv6).

For any connection that occurs over a tunnel, information about its
encapsulating tunnels is also found in the *tunnel* field of
:zeek:type:`connection`.

:Namespace: Tunnel

Summary
~~~~~~~
Redefinable Options
###################
================================================================================= ===============================================================
:zeek:id:`Tunnel::expiration_interval`: :zeek:type:`interval` :zeek:attr:`&redef` The amount of time a tunnel is not used in establishment of new
                                                                                  connections before it is considered inactive/expired.
================================================================================= ===============================================================

State Variables
###############
======================================================================================================================================================================== =========================
:zeek:id:`Tunnel::active`: :zeek:type:`table` :zeek:attr:`&read_expire` = :zeek:see:`Tunnel::expiration_interval` :zeek:attr:`&expire_func` = :zeek:see:`Tunnel::expire` Currently active tunnels.
======================================================================================================================================================================== =========================

Types
#####
============================================== ===============================================================
:zeek:type:`Tunnel::Action`: :zeek:type:`enum` Types of interesting activity that can occur with a tunnel.
:zeek:type:`Tunnel::Info`: :zeek:type:`record` The record type which contains column fields of the tunnel log.
============================================== ===============================================================

Redefinitions
#############
==================================================================== =====================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                              The tunnel logging stream identifier.
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== =====================================

Functions
#########
====================================================== ================================================================
:zeek:id:`Tunnel::close`: :zeek:type:`function`        Removes a single tunnel from the :zeek:id:`Tunnel::active` table
                                                       and logs the closing/expiration of the tunnel.
:zeek:id:`Tunnel::expire`: :zeek:type:`function`       Logs a single tunnel "connection" with action
                                                       :zeek:see:`Tunnel::EXPIRE` and removes it from the
                                                       :zeek:id:`Tunnel::active` table.
:zeek:id:`Tunnel::register`: :zeek:type:`function`     Logs a single tunnel "connection" with action
                                                       :zeek:see:`Tunnel::DISCOVER` if it's not already in the
                                                       :zeek:id:`Tunnel::active` table and adds it if not.
:zeek:id:`Tunnel::register_all`: :zeek:type:`function` Logs all tunnels in an encapsulation chain with action
                                                       :zeek:see:`Tunnel::DISCOVER` that aren't already in the
                                                       :zeek:id:`Tunnel::active` table and adds them if not.
====================================================== ================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Tunnel::expiration_interval

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 hr``

   The amount of time a tunnel is not used in establishment of new
   connections before it is considered inactive/expired.

State Variables
###############
.. zeek:id:: Tunnel::active

   :Type: :zeek:type:`table` [:zeek:type:`conn_id`] of :zeek:type:`Tunnel::Info`
   :Attributes: :zeek:attr:`&read_expire` = :zeek:see:`Tunnel::expiration_interval` :zeek:attr:`&expire_func` = :zeek:see:`Tunnel::expire`
   :Default: ``{}``

   Currently active tunnels.  That is, tunnels for which new,
   encapsulated connections have been seen in the interval indicated by
   :zeek:see:`Tunnel::expiration_interval`.

Types
#####
.. zeek:type:: Tunnel::Action

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Tunnel::DISCOVER Tunnel::Action

         A new tunnel (encapsulating "connection") has been seen.

      .. zeek:enum:: Tunnel::CLOSE Tunnel::Action

         A tunnel connection has closed.

      .. zeek:enum:: Tunnel::EXPIRE Tunnel::Action

         No new connections over a tunnel happened in the amount of
         time indicated by :zeek:see:`Tunnel::expiration_interval`.

   Types of interesting activity that can occur with a tunnel.

.. zeek:type:: Tunnel::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Time at which some tunnel activity occurred.

      uid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The unique identifier for the tunnel, which may correspond
         to a :zeek:type:`connection`'s *uid* field for non-IP-in-IP tunnels.
         This is optional because there could be numerous connections
         for payload proxies like SOCKS but we should treat it as a
         single tunnel.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The tunnel "connection" 4-tuple of endpoint addresses/ports.
         For an IP tunnel, the ports will be 0.

      tunnel_type: :zeek:type:`Tunnel::Type` :zeek:attr:`&log`
         The type of tunnel.

      action: :zeek:type:`Tunnel::Action` :zeek:attr:`&log`
         The type of activity that occurred.

   The record type which contains column fields of the tunnel log.

Functions
#########
.. zeek:id:: Tunnel::close

   :Type: :zeek:type:`function` (tunnel: :zeek:type:`Tunnel::Info`, action: :zeek:type:`Tunnel::Action`) : :zeek:type:`void`

   Removes a single tunnel from the :zeek:id:`Tunnel::active` table
   and logs the closing/expiration of the tunnel.
   

   :tunnel: The tunnel which has closed or expired.
   

   :action: The specific reason for the tunnel ending.

.. zeek:id:: Tunnel::expire

   :Type: :zeek:type:`function` (t: :zeek:type:`table` [:zeek:type:`conn_id`] of :zeek:type:`Tunnel::Info`, idx: :zeek:type:`conn_id`) : :zeek:type:`interval`

   Logs a single tunnel "connection" with action
   :zeek:see:`Tunnel::EXPIRE` and removes it from the
   :zeek:id:`Tunnel::active` table.
   

   :t: A table of tunnels.
   

   :idx: The index of the tunnel table corresponding to the tunnel to expire.
   

   :returns: 0secs, which when this function is used as an
            :zeek:attr:`&expire_func`, indicates to remove the element at
            *idx* immediately.

.. zeek:id:: Tunnel::register

   :Type: :zeek:type:`function` (ec: :zeek:type:`Tunnel::EncapsulatingConn`) : :zeek:type:`void`

   Logs a single tunnel "connection" with action
   :zeek:see:`Tunnel::DISCOVER` if it's not already in the
   :zeek:id:`Tunnel::active` table and adds it if not.

.. zeek:id:: Tunnel::register_all

   :Type: :zeek:type:`function` (ecv: :zeek:type:`EncapsulatingConnVector`) : :zeek:type:`void`

   Logs all tunnels in an encapsulation chain with action
   :zeek:see:`Tunnel::DISCOVER` that aren't already in the
   :zeek:id:`Tunnel::active` table and adds them if not.


