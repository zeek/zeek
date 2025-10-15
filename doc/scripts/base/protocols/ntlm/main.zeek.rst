:tocdepth: 3

base/protocols/ntlm/main.zeek
=============================
.. zeek:namespace:: NTLM


:Namespace: NTLM
:Imports: :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`

Summary
~~~~~~~
Types
#####
============================================ =
:zeek:type:`NTLM::Info`: :zeek:type:`record` 
============================================ =

Redefinitions
#############
======================================================================= ======================================================
:zeek:id:`DPD::ignore_violations`: :zeek:type:`set` :zeek:attr:`&redef` 
:zeek:type:`Log::ID`: :zeek:type:`enum`                                 
                                                                        
                                                                        * :zeek:enum:`NTLM::LOG`
:zeek:type:`connection`: :zeek:type:`record`                            
                                                                        
                                                                        :New Fields: :zeek:type:`connection`
                                                                        
                                                                          ntlm: :zeek:type:`NTLM::Info` :zeek:attr:`&optional`
======================================================================= ======================================================

Hooks
#####
============================================================== =======================
:zeek:id:`NTLM::finalize_ntlm`: :zeek:type:`Conn::RemovalHook` NTLM finalization hook.
:zeek:id:`NTLM::log_policy`: :zeek:type:`Log::PolicyHook`      
============================================================== =======================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: NTLM::Info
   :source-code: base/protocols/ntlm/main.zeek 10 38

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp for when the event happened.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique ID for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports.


   .. zeek:field:: username :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Username given by the client.


   .. zeek:field:: hostname :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Hostname given by the client.


   .. zeek:field:: domainname :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Domainname given by the client.


   .. zeek:field:: server_nb_computer_name :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      NetBIOS name given by the server in a CHALLENGE.


   .. zeek:field:: server_dns_computer_name :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      DNS name given by the server in a CHALLENGE.


   .. zeek:field:: server_tree_name :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Tree name given by the server in a CHALLENGE.


   .. zeek:field:: success :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`

      Indicate whether or not the authentication was successful.


   .. zeek:field:: done :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Internally used field to indicate if the login attempt
      has already been logged.



Hooks
#####
.. zeek:id:: NTLM::finalize_ntlm
   :source-code: base/protocols/ntlm/main.zeek 117 123

   :Type: :zeek:type:`Conn::RemovalHook`

   NTLM finalization hook.  Remaining NTLM info may get logged when it's called.

.. zeek:id:: NTLM::log_policy
   :source-code: base/protocols/ntlm/main.zeek 8 8

   :Type: :zeek:type:`Log::PolicyHook`



