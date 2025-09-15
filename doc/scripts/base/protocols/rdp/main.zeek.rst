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
   :source-code: base/protocols/rdp/main.zeek 67 67

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, detach the RDP analyzer from the connection to prevent
   continuing to process encrypted traffic.

.. zeek:id:: RDP::rdp_check_interval
   :source-code: base/protocols/rdp/main.zeek 71 71

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 secs``

   The amount of time to monitor an RDP session from when it is first
   identified. When this interval is reached, the session is logged.

Types
#####
.. zeek:type:: RDP::Info
   :source-code: base/protocols/rdp/main.zeek 13 63

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp for when the event happened.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique ID for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports.


   .. zeek:field:: cookie :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Cookie value used by the client machine.
      This is typically a username, but note that it will often
      be truncated on the wire, to a maximum of 9 characters.


   .. zeek:field:: result :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Status result for the connection.  It's a mix between
      RDP negotiation failure messages and GCC server create
      response messages.


   .. zeek:field:: security_protocol :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Security protocol chosen by the server.


   .. zeek:field:: client_channels :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The channels requested by the client


   .. zeek:field:: keyboard_layout :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Keyboard layout (language) of the client machine.


   .. zeek:field:: client_build :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      RDP client version used by the client machine.


   .. zeek:field:: client_name :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Name of the client machine.


   .. zeek:field:: client_dig_product_id :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Product ID of the client machine.


   .. zeek:field:: desktop_width :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      Desktop width of the client machine.


   .. zeek:field:: desktop_height :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      Desktop height of the client machine.


   .. zeek:field:: requested_color_depth :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The color depth requested by the client in
      the high_color_depth field.


   .. zeek:field:: cert_type :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      If the connection is being encrypted with native
      RDP encryption, this is the type of cert
      being used.


   .. zeek:field:: cert_count :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      The number of certs seen.  X.509 can transfer an
      entire certificate chain.


   .. zeek:field:: cert_permanent :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`

      Indicates if the provided certificate or certificate
      chain is permanent or temporary.


   .. zeek:field:: encryption_level :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Encryption level of the connection.


   .. zeek:field:: encryption_method :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Encryption method of the connection.


   .. zeek:field:: analyzer_id :zeek:type:`count` :zeek:attr:`&optional`

      The analyzer ID used for the analyzer instance attached
      to each connection.  It is not used for logging since it's a
      meaningless arbitrary number.


   .. zeek:field:: done :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Track status of logging RDP connections.


   .. zeek:field:: ssl :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/rdp/indicate_ssl.zeek` is loaded)

      Flag the connection if it was seen over SSL.



Events
######
.. zeek:id:: RDP::log_rdp
   :source-code: base/protocols/rdp/main.zeek 75 75

   :Type: :zeek:type:`event` (rec: :zeek:type:`RDP::Info`)

   Event that can be handled to access the rdp record as it is sent on
   to the logging framework.

Hooks
#####
.. zeek:id:: RDP::finalize_rdp
   :source-code: base/protocols/rdp/main.zeek 296 303

   :Type: :zeek:type:`Conn::RemovalHook`

   RDP finalization hook.  Remaining RDP info may get logged when it's called.

.. zeek:id:: RDP::log_policy
   :source-code: base/protocols/rdp/main.zeek 11 11

   :Type: :zeek:type:`Log::PolicyHook`



