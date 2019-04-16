:tocdepth: 3

base/protocols/socks/main.zeek
==============================
.. bro:namespace:: SOCKS


:Namespace: SOCKS
:Imports: :doc:`base/frameworks/tunnels </scripts/base/frameworks/tunnels/index>`, :doc:`base/protocols/socks/consts.zeek </scripts/base/protocols/socks/consts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================== ======================================
:bro:id:`SOCKS::default_capture_password`: :bro:type:`bool` :bro:attr:`&redef` Whether passwords are captured or not.
============================================================================== ======================================

Types
#####
=========================================== ===========================================================
:bro:type:`SOCKS::Info`: :bro:type:`record` The record type which contains the fields of the SOCKS log.
=========================================== ===========================================================

Redefinitions
#############
================================================================= =
:bro:type:`Log::ID`: :bro:type:`enum`                             
:bro:type:`connection`: :bro:type:`record`                        
:bro:id:`likely_server_ports`: :bro:type:`set` :bro:attr:`&redef` 
================================================================= =

Events
######
============================================= =================================================
:bro:id:`SOCKS::log_socks`: :bro:type:`event` Event that can be handled to access the SOCKS
                                              record as it is sent on to the logging framework.
============================================= =================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: SOCKS::default_capture_password

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   Whether passwords are captured or not.

Types
#####
.. bro:type:: SOCKS::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Time when the proxy connection was first detected.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique ID for the tunnel - may correspond to connection uid
         or be non-existent.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      version: :bro:type:`count` :bro:attr:`&log`
         Protocol version of SOCKS.

      user: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Username used to request a login to the proxy.

      password: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Password used to request a login to the proxy.

      status: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Server status for the attempt at using the proxy.

      request: :bro:type:`SOCKS::Address` :bro:attr:`&log` :bro:attr:`&optional`
         Client requested SOCKS address. Could be an address, a name
         or both.

      request_p: :bro:type:`port` :bro:attr:`&log` :bro:attr:`&optional`
         Client requested port.

      bound: :bro:type:`SOCKS::Address` :bro:attr:`&log` :bro:attr:`&optional`
         Server bound address. Could be an address, a name or both.

      bound_p: :bro:type:`port` :bro:attr:`&log` :bro:attr:`&optional`
         Server bound port.

      capture_password: :bro:type:`bool` :bro:attr:`&default` = :bro:see:`SOCKS::default_capture_password` :bro:attr:`&optional`
         Determines if the password will be captured for this request.

   The record type which contains the fields of the SOCKS log.

Events
######
.. bro:id:: SOCKS::log_socks

   :Type: :bro:type:`event` (rec: :bro:type:`SOCKS::Info`)

   Event that can be handled to access the SOCKS
   record as it is sent on to the logging framework.


