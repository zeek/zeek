:tocdepth: 3

base/protocols/ssh/main.zeek
============================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: SSH

Implements base functionality for SSH analysis. Generates the ssh.log file.

:Namespaces: GLOBAL, SSH
:Imports: :doc:`base/utils/directions-and-hosts.zeek </scripts/base/utils/directions-and-hosts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================================= ====================================================================
:zeek:id:`SSH::compression_algorithms`: :zeek:type:`set` :zeek:attr:`&redef`            The set of compression algorithms.
:zeek:id:`SSH::disable_analyzer_after_detection`: :zeek:type:`bool` :zeek:attr:`&redef` If true, after detection detach the SSH analyzer from the connection
                                                                                        to prevent continuing to process encrypted traffic.
======================================================================================= ====================================================================

Types
#####
=========================================== =========================================================
:zeek:type:`SSH::Info`: :zeek:type:`record` The record type which contains the fields of the SSH log.
=========================================== =========================================================

Redefinitions
#############
==================================================================== ===========================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                              The SSH protocol logging stream identifier.
:zeek:type:`SSH::Info`: :zeek:type:`record`                          
:zeek:type:`connection`: :zeek:type:`record`                         
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== ===========================================

Events
######
================================================== ===================================================================
:zeek:id:`SSH::log_ssh`: :zeek:type:`event`        Event that can be handled to access the SSH record as it is sent on
                                                   to the logging framework.
:zeek:id:`ssh_auth_failed`: :zeek:type:`event`     This event is generated when an :abbr:`SSH (Secure Shell)`
                                                   connection was determined to have had a failed authentication.
:zeek:id:`ssh_auth_result`: :zeek:type:`event`     This event is generated when a determination has been made about
                                                   the final authentication result of an :abbr:`SSH (Secure Shell)`
                                                   connection.
:zeek:id:`ssh_server_host_key`: :zeek:type:`event` Event that can be handled when the analyzer sees an SSH server host
                                                   key.
================================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SSH::compression_algorithms

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

   ::

      {
         "zlib",
         "zlib@openssh.com"
      }

   The set of compression algorithms. We can't accurately determine
   authentication success or failure when compression is enabled.

.. zeek:id:: SSH::disable_analyzer_after_detection

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   If true, after detection detach the SSH analyzer from the connection
   to prevent continuing to process encrypted traffic. Helps with performance
   (especially with large file transfers).

Types
#####
.. zeek:type:: SSH::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Time when the SSH connection began.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      version: :zeek:type:`count` :zeek:attr:`&log`
         SSH major version (1 or 2)

      auth_success: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`
         Authentication result (T=success, F=failure, unset=unknown)

      auth_attempts: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         The number of authentication attemps we observed. There's always
         at least one, since some servers might support no authentication at all.
         It's important to note that not all of these are failures, since
         some servers require two-factor auth (e.g. password AND pubkey)

      direction: :zeek:type:`Direction` :zeek:attr:`&log` :zeek:attr:`&optional`
         Direction of the connection. If the client was a local host
         logging into an external host, this would be OUTBOUND. INBOUND
         would be set for the opposite situation.

      client: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The client's version string

      server: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The server's version string

      cipher_alg: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The encryption algorithm in use

      mac_alg: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The signing (MAC) algorithm in use

      compression_alg: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The compression algorithm in use

      kex_alg: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The key exchange algorithm in use

      host_key_alg: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The server host key's algorithm

      host_key: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The server's key fingerprint

      logged: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      capabilities: :zeek:type:`SSH::Capabilities` :zeek:attr:`&optional`

      analyzer_id: :zeek:type:`count` :zeek:attr:`&optional`
         Analzyer ID

      remote_location: :zeek:type:`geo_location` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/ssh/geo-data.zeek` is loaded)

         Add geographic data related to the "remote" host of the
         connection.

   The record type which contains the fields of the SSH log.

Events
######
.. zeek:id:: SSH::log_ssh

   :Type: :zeek:type:`event` (rec: :zeek:type:`SSH::Info`)

   Event that can be handled to access the SSH record as it is sent on
   to the logging framework.

.. zeek:id:: ssh_auth_failed

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   This event is generated when an :abbr:`SSH (Secure Shell)`
   connection was determined to have had a failed authentication. This
   determination is based on packet size analysis, and errs on the
   side of caution - that is, if there's any doubt about the
   authentication failure, this event is *not* raised.
   
   This event is only raised once per connection.
   

   :c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   
   .. zeek:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_result ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key

.. zeek:id:: ssh_auth_result

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, result: :zeek:type:`bool`, auth_attempts: :zeek:type:`count`)

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
   
   .. zeek:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key

.. zeek:id:: ssh_server_host_key

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hash: :zeek:type:`string`)

   Event that can be handled when the analyzer sees an SSH server host
   key. This abstracts :zeek:id:`ssh1_server_host_key` and
   :zeek:id:`ssh2_server_host_key`.
   
   .. zeek:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_result
      ssh_auth_attempted ssh_capabilities ssh2_server_host_key
      ssh1_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key


