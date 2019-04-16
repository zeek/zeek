:tocdepth: 3

base/protocols/rdp/main.zeek
============================
.. bro:namespace:: RDP

Implements base functionality for RDP analysis. Generates the rdp.log file.

:Namespace: RDP
:Imports: :doc:`base/protocols/rdp/consts.zeek </scripts/base/protocols/rdp/consts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
==================================================================================== ===================================================================
:bro:id:`RDP::disable_analyzer_after_detection`: :bro:type:`bool` :bro:attr:`&redef` If true, detach the RDP analyzer from the connection to prevent
                                                                                     continuing to process encrypted traffic.
:bro:id:`RDP::rdp_check_interval`: :bro:type:`interval` :bro:attr:`&redef`           The amount of time to monitor an RDP session from when it is first 
                                                                                     identified.
==================================================================================== ===================================================================

Types
#####
========================================= =
:bro:type:`RDP::Info`: :bro:type:`record` 
========================================= =

Redefinitions
#############
================================================================= =
:bro:type:`Log::ID`: :bro:type:`enum`                             
:bro:type:`RDP::Info`: :bro:type:`record`                         
:bro:type:`connection`: :bro:type:`record`                        
:bro:id:`likely_server_ports`: :bro:type:`set` :bro:attr:`&redef` 
================================================================= =

Events
######
========================================= ===================================================================
:bro:id:`RDP::log_rdp`: :bro:type:`event` Event that can be handled to access the rdp record as it is sent on
                                          to the logging framework.
========================================= ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: RDP::disable_analyzer_after_detection

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, detach the RDP analyzer from the connection to prevent
   continuing to process encrypted traffic.

.. bro:id:: RDP::rdp_check_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``10.0 secs``

   The amount of time to monitor an RDP session from when it is first 
   identified. When this interval is reached, the session is logged.

Types
#####
.. bro:type:: RDP::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp for when the event happened.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique ID for the connection.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      cookie: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Cookie value used by the client machine.
         This is typically a username.

      result: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Status result for the connection.  It's a mix between
         RDP negotation failure messages and GCC server create
         response messages.

      security_protocol: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Security protocol chosen by the server.

      keyboard_layout: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Keyboard layout (language) of the client machine.

      client_build: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         RDP client version used by the client machine.

      client_name: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Name of the client machine.

      client_dig_product_id: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Product ID of the client machine.

      desktop_width: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         Desktop width of the client machine.

      desktop_height: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         Desktop height of the client machine.

      requested_color_depth: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The color depth requested by the client in 
         the high_color_depth field.

      cert_type: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         If the connection is being encrypted with native
         RDP encryption, this is the type of cert 
         being used.

      cert_count: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         The number of certs seen.  X.509 can transfer an 
         entire certificate chain.

      cert_permanent: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&optional`
         Indicates if the provided certificate or certificate
         chain is permanent or temporary.

      encryption_level: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Encryption level of the connection.

      encryption_method: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Encryption method of the connection. 

      analyzer_id: :bro:type:`count` :bro:attr:`&optional`
         The analyzer ID used for the analyzer instance attached
         to each connection.  It is not used for logging since it's a
         meaningless arbitrary number.

      done: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Track status of logging RDP connections.

      ssl: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/rdp/indicate_ssl.zeek` is loaded)

         Flag the connection if it was seen over SSL.


Events
######
.. bro:id:: RDP::log_rdp

   :Type: :bro:type:`event` (rec: :bro:type:`RDP::Info`)

   Event that can be handled to access the rdp record as it is sent on
   to the logging framework.


