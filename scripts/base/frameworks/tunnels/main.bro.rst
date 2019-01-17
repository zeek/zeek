:tocdepth: 3

base/frameworks/tunnels/main.bro
================================
.. bro:namespace:: Tunnel

This script handles the tracking/logging of tunnels (e.g. Teredo,
AYIYA, or IP-in-IP such as 6to4 where "IP" is either IPv4 or IPv6).

For any connection that occurs over a tunnel, information about its
encapsulating tunnels is also found in the *tunnel* field of
:bro:type:`connection`.

:Namespace: Tunnel

Summary
~~~~~~~
Redefinable Options
###################
============================================================================== ===============================================================
:bro:id:`Tunnel::expiration_interval`: :bro:type:`interval` :bro:attr:`&redef` The amount of time a tunnel is not used in establishment of new
                                                                               connections before it is considered inactive/expired.
============================================================================== ===============================================================

State Variables
###############
================================================================================================================================================================== =========================
:bro:id:`Tunnel::active`: :bro:type:`table` :bro:attr:`&read_expire` = :bro:see:`Tunnel::expiration_interval` :bro:attr:`&expire_func` = :bro:see:`Tunnel::expire` Currently active tunnels.
================================================================================================================================================================== =========================

Types
#####
============================================ ===============================================================
:bro:type:`Tunnel::Action`: :bro:type:`enum` Types of interesting activity that can occur with a tunnel.
:bro:type:`Tunnel::Info`: :bro:type:`record` The record type which contains column fields of the tunnel log.
============================================ ===============================================================

Redefinitions
#############
================================================================= =====================================
:bro:type:`Log::ID`: :bro:type:`enum`                             The tunnel logging stream identifier.
:bro:id:`likely_server_ports`: :bro:type:`set` :bro:attr:`&redef` 
================================================================= =====================================

Functions
#########
==================================================== ===============================================================
:bro:id:`Tunnel::close`: :bro:type:`function`        Removes a single tunnel from the :bro:id:`Tunnel::active` table
                                                     and logs the closing/expiration of the tunnel.
:bro:id:`Tunnel::expire`: :bro:type:`function`       Logs a single tunnel "connection" with action
                                                     :bro:see:`Tunnel::EXPIRE` and removes it from the
                                                     :bro:id:`Tunnel::active` table.
:bro:id:`Tunnel::register`: :bro:type:`function`     Logs a single tunnel "connection" with action
                                                     :bro:see:`Tunnel::DISCOVER` if it's not already in the
                                                     :bro:id:`Tunnel::active` table and adds it if not.
:bro:id:`Tunnel::register_all`: :bro:type:`function` Logs all tunnels in an encapsulation chain with action
                                                     :bro:see:`Tunnel::DISCOVER` that aren't already in the
                                                     :bro:id:`Tunnel::active` table and adds them if not.
==================================================== ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: Tunnel::expiration_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1.0 hr``

   The amount of time a tunnel is not used in establishment of new
   connections before it is considered inactive/expired.

State Variables
###############
.. bro:id:: Tunnel::active

   :Type: :bro:type:`table` [:bro:type:`conn_id`] of :bro:type:`Tunnel::Info`
   :Attributes: :bro:attr:`&read_expire` = :bro:see:`Tunnel::expiration_interval` :bro:attr:`&expire_func` = :bro:see:`Tunnel::expire`
   :Default: ``{}``

   Currently active tunnels.  That is, tunnels for which new,
   encapsulated connections have been seen in the interval indicated by
   :bro:see:`Tunnel::expiration_interval`.

Types
#####
.. bro:type:: Tunnel::Action

   :Type: :bro:type:`enum`

      .. bro:enum:: Tunnel::DISCOVER Tunnel::Action

         A new tunnel (encapsulating "connection") has been seen.

      .. bro:enum:: Tunnel::CLOSE Tunnel::Action

         A tunnel connection has closed.

      .. bro:enum:: Tunnel::EXPIRE Tunnel::Action

         No new connections over a tunnel happened in the amount of
         time indicated by :bro:see:`Tunnel::expiration_interval`.

   Types of interesting activity that can occur with a tunnel.

.. bro:type:: Tunnel::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Time at which some tunnel activity occurred.

      uid: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The unique identifier for the tunnel, which may correspond
         to a :bro:type:`connection`'s *uid* field for non-IP-in-IP tunnels.
         This is optional because there could be numerous connections
         for payload proxies like SOCKS but we should treat it as a
         single tunnel.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         The tunnel "connection" 4-tuple of endpoint addresses/ports.
         For an IP tunnel, the ports will be 0.

      tunnel_type: :bro:type:`Tunnel::Type` :bro:attr:`&log`
         The type of tunnel.

      action: :bro:type:`Tunnel::Action` :bro:attr:`&log`
         The type of activity that occurred.

   The record type which contains column fields of the tunnel log.

Functions
#########
.. bro:id:: Tunnel::close

   :Type: :bro:type:`function` (tunnel: :bro:type:`Tunnel::Info`, action: :bro:type:`Tunnel::Action`) : :bro:type:`void`

   Removes a single tunnel from the :bro:id:`Tunnel::active` table
   and logs the closing/expiration of the tunnel.
   

   :tunnel: The tunnel which has closed or expired.
   

   :action: The specific reason for the tunnel ending.

.. bro:id:: Tunnel::expire

   :Type: :bro:type:`function` (t: :bro:type:`table` [:bro:type:`conn_id`] of :bro:type:`Tunnel::Info`, idx: :bro:type:`conn_id`) : :bro:type:`interval`

   Logs a single tunnel "connection" with action
   :bro:see:`Tunnel::EXPIRE` and removes it from the
   :bro:id:`Tunnel::active` table.
   

   :t: A table of tunnels.
   

   :idx: The index of the tunnel table corresponding to the tunnel to expire.
   

   :returns: 0secs, which when this function is used as an
            :bro:attr:`&expire_func`, indicates to remove the element at
            *idx* immediately.

.. bro:id:: Tunnel::register

   :Type: :bro:type:`function` (ec: :bro:type:`Tunnel::EncapsulatingConn`) : :bro:type:`void`

   Logs a single tunnel "connection" with action
   :bro:see:`Tunnel::DISCOVER` if it's not already in the
   :bro:id:`Tunnel::active` table and adds it if not.

.. bro:id:: Tunnel::register_all

   :Type: :bro:type:`function` (ecv: :bro:type:`EncapsulatingConnVector`) : :bro:type:`void`

   Logs all tunnels in an encapsulation chain with action
   :bro:see:`Tunnel::DISCOVER` that aren't already in the
   :bro:id:`Tunnel::active` table and adds them if not.


