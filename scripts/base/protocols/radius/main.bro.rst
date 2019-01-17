:tocdepth: 3

base/protocols/radius/main.bro
==============================
.. bro:namespace:: RADIUS

Implements base functionality for RADIUS analysis. Generates the radius.log file.

:Namespace: RADIUS
:Imports: :doc:`base/protocols/radius/consts.bro </scripts/base/protocols/radius/consts.bro>`, :doc:`base/utils/addrs.bro </scripts/base/utils/addrs.bro>`

Summary
~~~~~~~
Types
#####
============================================ =
:bro:type:`RADIUS::Info`: :bro:type:`record` 
============================================ =

Redefinitions
#############
================================================================= =
:bro:type:`Log::ID`: :bro:type:`enum`                             
:bro:type:`connection`: :bro:type:`record`                        
:bro:id:`likely_server_ports`: :bro:type:`set` :bro:attr:`&redef` 
================================================================= =

Events
######
=============================================== ======================================================================
:bro:id:`RADIUS::log_radius`: :bro:type:`event` Event that can be handled to access the RADIUS record as it is sent on
                                                to the logging framework.
=============================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: RADIUS::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp for when the event happened.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique ID for the connection.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      username: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The username, if present.

      mac: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         MAC address, if present.

      framed_addr: :bro:type:`addr` :bro:attr:`&log` :bro:attr:`&optional`
         The address given to the network access server, if
         present.  This is only a hint from the RADIUS server
         and the network access server is not required to honor 
         the address.

      remote_ip: :bro:type:`addr` :bro:attr:`&log` :bro:attr:`&optional`
         Remote IP address, if present.  This is collected
         from the Tunnel-Client-Endpoint attribute.

      connect_info: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Connect info, if present.

      reply_msg: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Reply message from the server challenge. This is 
         frequently shown to the user authenticating.

      result: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Successful or failed authentication.

      ttl: :bro:type:`interval` :bro:attr:`&log` :bro:attr:`&optional`
         The duration between the first request and
         either the "Access-Accept" message or an error.
         If the field is empty, it means that either
         the request or response was not seen.

      logged: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Whether this has already been logged and can be ignored.


Events
######
.. bro:id:: RADIUS::log_radius

   :Type: :bro:type:`event` (rec: :bro:type:`RADIUS::Info`)

   Event that can be handled to access the RADIUS record as it is sent on
   to the logging framework.


