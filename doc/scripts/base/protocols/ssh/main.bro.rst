:tocdepth: 3

base/protocols/ssh/main.bro
===========================
.. bro:namespace:: GLOBAL
.. bro:namespace:: SSH

Implements base functionality for SSH analysis. Generates the ssh.log file.

:Namespaces: GLOBAL, SSH
:Imports: :doc:`base/utils/directions-and-hosts.bro </scripts/base/utils/directions-and-hosts.bro>`

Summary
~~~~~~~
Runtime Options
###############
==================================================================================== ====================================================================
:bro:id:`SSH::compression_algorithms`: :bro:type:`set` :bro:attr:`&redef`            The set of compression algorithms.
:bro:id:`SSH::disable_analyzer_after_detection`: :bro:type:`bool` :bro:attr:`&redef` If true, after detection detach the SSH analyzer from the connection
                                                                                     to prevent continuing to process encrypted traffic.
==================================================================================== ====================================================================

Types
#####
========================================= =========================================================
:bro:type:`SSH::Info`: :bro:type:`record` The record type which contains the fields of the SSH log.
========================================= =========================================================

Redefinitions
#############
================================================================= ===========================================
:bro:type:`Log::ID`: :bro:type:`enum`                             The SSH protocol logging stream identifier.
:bro:type:`SSH::Info`: :bro:type:`record`                         
:bro:type:`connection`: :bro:type:`record`                        
:bro:id:`likely_server_ports`: :bro:type:`set` :bro:attr:`&redef` 
================================================================= ===========================================

Events
######
================================================ ===================================================================
:bro:id:`SSH::log_ssh`: :bro:type:`event`        Event that can be handled to access the SSH record as it is sent on
                                                 to the logging framework.
:bro:id:`ssh_auth_failed`: :bro:type:`event`     This event is generated when an :abbr:`SSH (Secure Shell)`
                                                 connection was determined to have had a failed authentication.
:bro:id:`ssh_auth_result`: :bro:type:`event`     This event is generated when a determination has been made about
                                                 the final authentication result of an :abbr:`SSH (Secure Shell)`
                                                 connection.
:bro:id:`ssh_server_host_key`: :bro:type:`event` Event that can be handled when the analyzer sees an SSH server host
                                                 key.
================================================ ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: SSH::compression_algorithms

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         "zlib",
         "zlib@openssh.com"
      }

   The set of compression algorithms. We can't accurately determine
   authentication success or failure when compression is enabled.

.. bro:id:: SSH::disable_analyzer_after_detection

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   If true, after detection detach the SSH analyzer from the connection
   to prevent continuing to process encrypted traffic. Helps with performance
   (especially with large file transfers).

Types
#####
.. bro:type:: SSH::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Time when the SSH connection began.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique ID for the connection.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      version: :bro:type:`count` :bro:attr:`&log`
         SSH major version (1 or 2)

      auth_success: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&optional`
         Authentication result (T=success, F=failure, unset=unknown)

      auth_attempts: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         The number of authentication attemps we observed. There's always
         at least one, since some servers might support no authentication at all.
         It's important to note that not all of these are failures, since
         some servers require two-factor auth (e.g. password AND pubkey)

      direction: :bro:type:`Direction` :bro:attr:`&log` :bro:attr:`&optional`
         Direction of the connection. If the client was a local host
         logging into an external host, this would be OUTBOUND. INBOUND
         would be set for the opposite situation.

      client: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The client's version string

      server: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The server's version string

      cipher_alg: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The encryption algorithm in use

      mac_alg: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The signing (MAC) algorithm in use

      compression_alg: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The compression algorithm in use

      kex_alg: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The key exchange algorithm in use

      host_key_alg: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The server host key's algorithm

      host_key: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The server's key fingerprint

      logged: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`

      capabilities: :bro:type:`SSH::Capabilities` :bro:attr:`&optional`

      analyzer_id: :bro:type:`count` :bro:attr:`&optional`
         Analzyer ID

      remote_location: :bro:type:`geo_location` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/ssh/geo-data.bro` is loaded)

         Add geographic data related to the "remote" host of the
         connection.

   The record type which contains the fields of the SSH log.

Events
######
.. bro:id:: SSH::log_ssh

   :Type: :bro:type:`event` (rec: :bro:type:`SSH::Info`)

   Event that can be handled to access the SSH record as it is sent on
   to the logging framework.

.. bro:id:: ssh_auth_failed

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   This event is generated when an :abbr:`SSH (Secure Shell)`
   connection was determined to have had a failed authentication. This
   determination is based on packet size analysis, and errs on the
   side of caution - that is, if there's any doubt about the
   authentication failure, this event is *not* raised.
   
   This event is only raised once per connection.
   

   :c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_result ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key

.. bro:id:: ssh_auth_result

   :Type: :bro:type:`event` (c: :bro:type:`connection`, result: :bro:type:`bool`, auth_attempts: :bro:type:`count`)

   This event is generated when a determination has been made about
   the final authentication result of an :abbr:`SSH (Secure Shell)`
   connection. This determination is based on packet size analysis,
   and errs on the side of caution - that is, if there's any doubt
   about the result of the authentication, this event is *not* raised.
   
   This event is only raised once per connection.
   

   :c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :result: True if the authentication was successful, false if not.
   

   :auth_attempts: The number of authentication attempts that were
      observed.
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key

.. bro:id:: ssh_server_host_key

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hash: :bro:type:`string`)

   Event that can be handled when the analyzer sees an SSH server host
   key. This abstracts :bro:id:`ssh1_server_host_key` and
   :bro:id:`ssh2_server_host_key`.
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_result
      ssh_auth_attempted ssh_capabilities ssh2_server_host_key
      ssh1_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key


