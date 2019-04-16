:tocdepth: 3

base/protocols/dnp3/main.zeek
=============================
.. bro:namespace:: DNP3

A very basic DNP3 analysis script that just logs requests and replies.

:Namespace: DNP3
:Imports: :doc:`base/protocols/dnp3/consts.zeek </scripts/base/protocols/dnp3/consts.zeek>`

Summary
~~~~~~~
Types
#####
========================================== =
:bro:type:`DNP3::Info`: :bro:type:`record` 
========================================== =

Redefinitions
#############
================================================================= =
:bro:type:`Log::ID`: :bro:type:`enum`                             
:bro:type:`connection`: :bro:type:`record`                        
:bro:id:`likely_server_ports`: :bro:type:`set` :bro:attr:`&redef` 
================================================================= =

Events
######
=========================================== ====================================================================
:bro:id:`DNP3::log_dnp3`: :bro:type:`event` Event that can be handled to access the DNP3 record as it is sent on
                                            to the logging framework.
=========================================== ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: DNP3::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Time of the request.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique identifier for the connection.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         Identifier for the connection.

      fc_request: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The name of the function message in the request.

      fc_reply: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The name of the function message in the reply.

      iin: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         The response's "internal indication number".


Events
######
.. bro:id:: DNP3::log_dnp3

   :Type: :bro:type:`event` (rec: :bro:type:`DNP3::Info`)

   Event that can be handled to access the DNP3 record as it is sent on
   to the logging framework.


