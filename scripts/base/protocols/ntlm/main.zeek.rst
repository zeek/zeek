:tocdepth: 3

base/protocols/ntlm/main.zeek
=============================
.. bro:namespace:: NTLM


:Namespace: NTLM
:Imports: :doc:`base/frameworks/dpd </scripts/base/frameworks/dpd/index>`

Summary
~~~~~~~
Types
#####
========================================== =
:bro:type:`NTLM::Info`: :bro:type:`record` 
========================================== =

Redefinitions
#############
==================================================================== =
:bro:id:`DPD::ignore_violations`: :bro:type:`set` :bro:attr:`&redef` 
:bro:type:`Log::ID`: :bro:type:`enum`                                
:bro:type:`connection`: :bro:type:`record`                           
==================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: NTLM::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp for when the event happened.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique ID for the connection.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      username: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Username given by the client.

      hostname: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Hostname given by the client.

      domainname: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Domainname given by the client.

      server_nb_computer_name: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         NetBIOS name given by the server in a CHALLENGE.

      server_dns_computer_name: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         DNS name given by the server in a CHALLENGE.

      server_tree_name: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Tree name given by the server in a CHALLENGE.

      success: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&optional`
         Indicate whether or not the authentication was successful.

      done: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Internally used field to indicate if the login attempt 
         has already been logged.



