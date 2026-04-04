:tocdepth: 3

base/protocols/radius/main.zeek
===============================
.. zeek:namespace:: RADIUS

Implements base functionality for RADIUS analysis. Generates the radius.log file.

:Namespace: RADIUS
:Imports: :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/radius/consts.zeek </scripts/base/protocols/radius/consts.zeek>`, :doc:`base/utils/addrs.zeek </scripts/base/utils/addrs.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
============================================================== ============================
:zeek:id:`RADIUS::ports`: :zeek:type:`set` :zeek:attr:`&redef` Well-known ports for RADIUS.
============================================================== ============================

Types
#####
============================================== =
:zeek:type:`RADIUS::Info`: :zeek:type:`record`
============================================== =

Redefinitions
#############
============================================ ==========================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`

                                             * :zeek:enum:`RADIUS::LOG`
:zeek:type:`connection`: :zeek:type:`record`

                                             :New Fields: :zeek:type:`connection`

                                               radius: :zeek:type:`RADIUS::Info` :zeek:attr:`&optional`
============================================ ==========================================================

Events
######
================================================= ======================================================================
:zeek:id:`RADIUS::log_radius`: :zeek:type:`event` Event that can be handled to access the RADIUS record as it is sent on
                                                  to the logging framework.
================================================= ======================================================================

Hooks
#####
================================================================== =========================
:zeek:id:`RADIUS::finalize_radius`: :zeek:type:`Conn::RemovalHook` RADIUS finalization hook.
:zeek:id:`RADIUS::log_policy`: :zeek:type:`Log::PolicyHook`
================================================================== =========================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: RADIUS::ports
   :source-code: base/protocols/radius/main.zeek 13 13

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            1812/udp
         }


   Well-known ports for RADIUS.

Types
#####
.. zeek:type:: RADIUS::Info
   :source-code: base/protocols/radius/main.zeek 17 52

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp for when the event happened.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique ID for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports.


   .. zeek:field:: username :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The username, if present.


   .. zeek:field:: mac :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      MAC address, if present.


   .. zeek:field:: framed_addr :zeek:type:`addr` :zeek:attr:`&log` :zeek:attr:`&optional`

      The address given to the network access server, if
      present.  This is only a hint from the RADIUS server
      and the network access server is not required to honor
      the address.


   .. zeek:field:: tunnel_client :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Address (IPv4, IPv6, or FQDN) of the initiator end of the tunnel,
      if present.  This is collected from the Tunnel-Client-Endpoint
      attribute.


   .. zeek:field:: connect_info :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Connect info, if present.


   .. zeek:field:: reply_msg :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Reply message from the server challenge. This is
      frequently shown to the user authenticating.


   .. zeek:field:: result :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Successful or failed authentication.


   .. zeek:field:: ttl :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&optional`

      The duration between the first request and
      either the "Access-Accept" message or an error.
      If the field is empty, it means that either
      the request or response was not seen.


   .. zeek:field:: logged :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Whether this has already been logged and can be ignored.



Events
######
.. zeek:id:: RADIUS::log_radius
   :source-code: base/protocols/radius/main.zeek 56 56

   :Type: :zeek:type:`event` (rec: :zeek:type:`RADIUS::Info`)

   Event that can be handled to access the RADIUS record as it is sent on
   to the logging framework.

Hooks
#####
.. zeek:id:: RADIUS::finalize_radius
   :source-code: base/protocols/radius/main.zeek 148 155

   :Type: :zeek:type:`Conn::RemovalHook`

   RADIUS finalization hook.  Remaining RADIUS info may get logged when it's called.

.. zeek:id:: RADIUS::log_policy
   :source-code: base/protocols/radius/main.zeek 15 15

   :Type: :zeek:type:`Log::PolicyHook`



