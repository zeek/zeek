:tocdepth: 3

base/protocols/socks/main.zeek
==============================
.. zeek:namespace:: SOCKS


:Namespace: SOCKS
:Imports: :doc:`base/frameworks/tunnels </scripts/base/frameworks/tunnels/index>`, :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/socks/consts.zeek </scripts/base/protocols/socks/consts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
================================================================================= ======================================
:zeek:id:`SOCKS::default_capture_password`: :zeek:type:`bool` :zeek:attr:`&redef` Whether passwords are captured or not.
================================================================================= ======================================

Types
#####
============================================= ===========================================================
:zeek:type:`SOCKS::Info`: :zeek:type:`record` The record type which contains the fields of the SOCKS log.
============================================= ===========================================================

Redefinitions
#############
==================================================================== ========================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                              
                                                                     
                                                                     * :zeek:enum:`SOCKS::LOG`
:zeek:type:`connection`: :zeek:type:`record`                         
                                                                     
                                                                     :New Fields: :zeek:type:`connection`
                                                                     
                                                                       socks: :zeek:type:`SOCKS::Info` :zeek:attr:`&optional`
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== ========================================================

Events
######
=============================================== =================================================
:zeek:id:`SOCKS::log_socks`: :zeek:type:`event` Event that can be handled to access the SOCKS
                                                record as it is sent on to the logging framework.
=============================================== =================================================

Hooks
#####
================================================================ ========================
:zeek:id:`SOCKS::finalize_socks`: :zeek:type:`Conn::RemovalHook` SOCKS finalization hook.
:zeek:id:`SOCKS::log_policy`: :zeek:type:`Log::PolicyHook`       
================================================================ ========================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SOCKS::default_capture_password
   :source-code: base/protocols/socks/main.zeek 13 13

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Whether passwords are captured or not.

Types
#####
.. zeek:type:: SOCKS::Info
   :source-code: base/protocols/socks/main.zeek 16 43

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Time when the proxy connection was first detected.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID for the tunnel - may correspond to connection uid
         or be nonexistent.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      version: :zeek:type:`count` :zeek:attr:`&log`
         Protocol version of SOCKS.

      user: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Username used to request a login to the proxy.

      password: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Password used to request a login to the proxy.

      status: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Server status for the attempt at using the proxy.

      request: :zeek:type:`SOCKS::Address` :zeek:attr:`&log` :zeek:attr:`&optional`
         Client requested SOCKS address. Could be an address, a name
         or both.

      request_p: :zeek:type:`port` :zeek:attr:`&log` :zeek:attr:`&optional`
         Client requested port.

      bound: :zeek:type:`SOCKS::Address` :zeek:attr:`&log` :zeek:attr:`&optional`
         Server bound address. Could be an address, a name or both.

      bound_p: :zeek:type:`port` :zeek:attr:`&log` :zeek:attr:`&optional`
         Server bound port.

      capture_password: :zeek:type:`bool` :zeek:attr:`&default` = :zeek:see:`SOCKS::default_capture_password` :zeek:attr:`&optional`
         Determines if the password will be captured for this request.

   The record type which contains the fields of the SOCKS log.

Events
######
.. zeek:id:: SOCKS::log_socks
   :source-code: base/protocols/socks/main.zeek 47 47

   :Type: :zeek:type:`event` (rec: :zeek:type:`SOCKS::Info`)

   Event that can be handled to access the SOCKS
   record as it is sent on to the logging framework.

Hooks
#####
.. zeek:id:: SOCKS::finalize_socks
   :source-code: base/protocols/socks/main.zeek 123 129

   :Type: :zeek:type:`Conn::RemovalHook`

   SOCKS finalization hook.  Remaining SOCKS info may get logged when it's called.

.. zeek:id:: SOCKS::log_policy
   :source-code: base/protocols/socks/main.zeek 10 10

   :Type: :zeek:type:`Log::PolicyHook`



