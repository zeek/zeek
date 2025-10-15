:tocdepth: 3

base/protocols/ssh/main.zeek
============================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: SSH

Implements base functionality for SSH analysis. Generates the ssh.log file.

:Namespaces: GLOBAL, SSH
:Imports: :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/utils/directions-and-hosts.zeek </scripts/base/utils/directions-and-hosts.zeek>`

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
==================================================================== ================================================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                              The SSH protocol logging stream identifier.
                                                                     
                                                                     * :zeek:enum:`SSH::LOG`
:zeek:type:`SSH::Info`: :zeek:type:`record`                          
                                                                     
                                                                     :New Fields: :zeek:type:`SSH::Info`
                                                                     
                                                                       logged: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
                                                                     
                                                                       capabilities: :zeek:type:`SSH::Capabilities` :zeek:attr:`&optional`
                                                                     
                                                                       analyzer_id: :zeek:type:`count` :zeek:attr:`&optional`
                                                                         Analyzer ID
:zeek:type:`connection`: :zeek:type:`record`                         
                                                                     
                                                                     :New Fields: :zeek:type:`connection`
                                                                     
                                                                       ssh: :zeek:type:`SSH::Info` :zeek:attr:`&optional`
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== ================================================================================

Events
######
============================================== ===================================================================
:zeek:id:`SSH::log_ssh`: :zeek:type:`event`    Event that can be handled to access the SSH record as it is sent on
                                               to the logging framework.
:zeek:id:`ssh_auth_failed`: :zeek:type:`event` This event is generated when an :abbr:`SSH (Secure Shell)`
                                               connection was determined to have had a failed authentication.
:zeek:id:`ssh_auth_result`: :zeek:type:`event` This event is generated when a determination has been made about
                                               the final authentication result of an :abbr:`SSH (Secure Shell)`
                                               connection.
============================================== ===================================================================

Hooks
#####
============================================================ =============================================
:zeek:id:`SSH::finalize_ssh`: :zeek:type:`Conn::RemovalHook` SSH finalization hook.
:zeek:id:`SSH::log_policy`: :zeek:type:`Log::PolicyHook`     A default logging policy hook for the stream.
============================================================ =============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SSH::compression_algorithms
   :source-code: base/protocols/ssh/main.zeek 61 61

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            "zlib@openssh.com",
            "zlib"
         }


   The set of compression algorithms. We can't accurately determine
   authentication success or failure when compression is enabled.

.. zeek:id:: SSH::disable_analyzer_after_detection
   :source-code: base/protocols/ssh/main.zeek 66 66

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   If true, after detection detach the SSH analyzer from the connection
   to prevent continuing to process encrypted traffic. Helps with performance
   (especially with large file transfers).

Types
#####
.. zeek:type:: SSH::Info
   :source-code: base/protocols/ssh/main.zeek 16 57

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Time when the SSH connection began.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      version: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
         SSH major version (1, 2, or unset). The version can be unset if the
         client and server version strings are unset, malformed or incompatible
         so no common version can be extracted. If no version can be extracted
         even though both client and server versions are set a weird
         will be generated.

      auth_success: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`
         Authentication result (T=success, F=failure, unset=unknown)

      auth_attempts: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         The number of authentication attempts we observed. There's always
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
         Analyzer ID

      remote_location: :zeek:type:`geo_location` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/ssh/geo-data.zeek` is loaded)

         Add geographic data related to the "remote" host of the
         connection.

   The record type which contains the fields of the SSH log.

Events
######
.. zeek:id:: SSH::log_ssh
   :source-code: base/protocols/ssh/main.zeek 70 70

   :Type: :zeek:type:`event` (rec: :zeek:type:`SSH::Info`)

   Event that can be handled to access the SSH record as it is sent on
   to the logging framework.

.. zeek:id:: ssh_auth_failed
   :source-code: base/protocols/ssh/main.zeek 94 94

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   This event is generated when an :abbr:`SSH (Secure Shell)`
   connection was determined to have had a failed authentication. This
   determination is based on packet size analysis, and errs on the
   side of caution - that is, if there's any doubt about the
   authentication failure, this event is *not* raised.
   
   This event is only raised once per connection.
   

   :param c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   
   .. zeek:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_result ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key

.. zeek:id:: ssh_auth_result
   :source-code: base/protocols/ssh/main.zeek 117 117

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, result: :zeek:type:`bool`, auth_attempts: :zeek:type:`count`)

   This event is generated when a determination has been made about
   the final authentication result of an :abbr:`SSH (Secure Shell)`
   connection. This determination is based on packet size analysis,
   and errs on the side of caution - that is, if there's any doubt
   about the result of the authentication, this event is *not* raised.
   
   This event is only raised once per connection.
   

   :param c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :param result: True if the authentication was successful, false if not.
   

   :param auth_attempts: The number of authentication attempts that were
      observed.
   
   .. zeek:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key

Hooks
#####
.. zeek:id:: SSH::finalize_ssh
   :source-code: base/protocols/ssh/main.zeek 312 336

   :Type: :zeek:type:`Conn::RemovalHook`

   SSH finalization hook.  Remaining SSH info may get logged when it's called.

.. zeek:id:: SSH::log_policy
   :source-code: base/protocols/ssh/main.zeek 13 13

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


