:tocdepth: 3

base/protocols/rdp/main.zeek
============================
.. zeek:namespace:: RDP

Implements base functionality for RDP analysis. Generates the rdp.log file.

:Namespace: RDP
:Imports: :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/rdp/consts.zeek </scripts/base/protocols/rdp/consts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================================= ==================================================================
:zeek:id:`RDP::disable_analyzer_after_detection`: :zeek:type:`bool` :zeek:attr:`&redef` If true, detach the RDP analyzer from the connection to prevent
                                                                                        continuing to process encrypted traffic.
:zeek:id:`RDP::rdp_check_interval`: :zeek:type:`interval` :zeek:attr:`&redef`           The amount of time to monitor an RDP session from when it is first
                                                                                        identified.
======================================================================================= ==================================================================

Types
#####
=========================================== =
:zeek:type:`RDP::Info`: :zeek:type:`record` 
=========================================== =

Redefinitions
#############
==================================================================== ==============================================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                              
                                                                     
                                                                     * :zeek:enum:`RDP::LOG`
:zeek:type:`RDP::Info`: :zeek:type:`record`                          
                                                                     
                                                                     :New Fields: :zeek:type:`RDP::Info`
                                                                     
                                                                       analyzer_id: :zeek:type:`count` :zeek:attr:`&optional`
                                                                         The analyzer ID used for the analyzer instance attached
                                                                         to each connection.
                                                                     
                                                                       done: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
                                                                         Track status of logging RDP connections.
:zeek:type:`connection`: :zeek:type:`record`                         
                                                                     
                                                                     :New Fields: :zeek:type:`connection`
                                                                     
                                                                       rdp: :zeek:type:`RDP::Info` :zeek:attr:`&optional`
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== ==============================================================================

Events
######
=========================================== ===================================================================
:zeek:id:`RDP::log_rdp`: :zeek:type:`event` Event that can be handled to access the rdp record as it is sent on
                                            to the logging framework.
=========================================== ===================================================================

Hooks
#####
============================================================ ======================
:zeek:id:`RDP::finalize_rdp`: :zeek:type:`Conn::RemovalHook` RDP finalization hook.
:zeek:id:`RDP::log_policy`: :zeek:type:`Log::PolicyHook`     
============================================================ ======================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: RDP::disable_analyzer_after_detection
   :source-code: base/protocols/rdp/main.zeek 66 66

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, detach the RDP analyzer from the connection to prevent
   continuing to process encrypted traffic.

.. zeek:id:: RDP::rdp_check_interval
   :source-code: base/protocols/rdp/main.zeek 70 70

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 secs``

   The amount of time to monitor an RDP session from when it is first
   identified. When this interval is reached, the session is logged.

Types
#####
.. zeek:type:: RDP::Info
   :source-code: base/protocols/rdp/main.zeek 13 62

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp for when the event happened.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      cookie: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Cookie value used by the client machine.
         This is typically a username.

      result: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Status result for the connection.  It's a mix between
         RDP negotiation failure messages and GCC server create
         response messages.

      security_protocol: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Security protocol chosen by the server.

      client_channels: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The channels requested by the client

      keyboard_layout: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Keyboard layout (language) of the client machine.

      client_build: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         RDP client version used by the client machine.

      client_name: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Name of the client machine.

      client_dig_product_id: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Product ID of the client machine.

      desktop_width: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
         Desktop width of the client machine.

      desktop_height: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
         Desktop height of the client machine.

      requested_color_depth: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The color depth requested by the client in
         the high_color_depth field.

      cert_type: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         If the connection is being encrypted with native
         RDP encryption, this is the type of cert
         being used.

      cert_count: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         The number of certs seen.  X.509 can transfer an
         entire certificate chain.

      cert_permanent: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`
         Indicates if the provided certificate or certificate
         chain is permanent or temporary.

      encryption_level: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Encryption level of the connection.

      encryption_method: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Encryption method of the connection.

      analyzer_id: :zeek:type:`count` :zeek:attr:`&optional`
         The analyzer ID used for the analyzer instance attached
         to each connection.  It is not used for logging since it's a
         meaningless arbitrary number.

      done: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         Track status of logging RDP connections.

      ssl: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/rdp/indicate_ssl.zeek` is loaded)

         Flag the connection if it was seen over SSL.


Events
######
.. zeek:id:: RDP::log_rdp
   :source-code: base/protocols/rdp/main.zeek 74 74

   :Type: :zeek:type:`event` (rec: :zeek:type:`RDP::Info`)

   Event that can be handled to access the rdp record as it is sent on
   to the logging framework.

Hooks
#####
.. zeek:id:: RDP::finalize_rdp
   :source-code: base/protocols/rdp/main.zeek 295 302

   :Type: :zeek:type:`Conn::RemovalHook`

   RDP finalization hook.  Remaining RDP info may get logged when it's called.

.. zeek:id:: RDP::log_policy
   :source-code: base/protocols/rdp/main.zeek 11 11

   :Type: :zeek:type:`Log::PolicyHook`



