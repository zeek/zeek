:tocdepth: 3

base/protocols/dnp3/main.zeek
=============================
.. zeek:namespace:: DNP3

A very basic DNP3 analysis script that just logs requests and replies.

:Namespace: DNP3
:Imports: :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/dnp3/consts.zeek </scripts/base/protocols/dnp3/consts.zeek>`

Summary
~~~~~~~
Types
#####
============================================ =
:zeek:type:`DNP3::Info`: :zeek:type:`record` 
============================================ =

Redefinitions
#############
==================================================================== ======================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                              
                                                                     
                                                                     * :zeek:enum:`DNP3::LOG`
:zeek:type:`connection`: :zeek:type:`record`                         
                                                                     
                                                                     :New Fields: :zeek:type:`connection`
                                                                     
                                                                       dnp3: :zeek:type:`DNP3::Info` :zeek:attr:`&optional`
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== ======================================================

Events
######
============================================= ====================================================================
:zeek:id:`DNP3::log_dnp3`: :zeek:type:`event` Event that can be handled to access the DNP3 record as it is sent on
                                              to the logging framework.
============================================= ====================================================================

Hooks
#####
============================================================== =======================
:zeek:id:`DNP3::finalize_dnp3`: :zeek:type:`Conn::RemovalHook` DNP3 finalization hook.
:zeek:id:`DNP3::log_policy`: :zeek:type:`Log::PolicyHook`      
============================================================== =======================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: DNP3::Info
   :source-code: base/protocols/dnp3/main.zeek 13 26

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Time of the request.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique identifier for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         Identifier for the connection.

      fc_request: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The name of the function message in the request.

      fc_reply: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The name of the function message in the reply.

      iin: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
         The response's "internal indication number".


Events
######
.. zeek:id:: DNP3::log_dnp3
   :source-code: base/protocols/dnp3/main.zeek 30 30

   :Type: :zeek:type:`event` (rec: :zeek:type:`DNP3::Info`)

   Event that can be handled to access the DNP3 record as it is sent on
   to the logging framework.

Hooks
#####
.. zeek:id:: DNP3::finalize_dnp3
   :source-code: base/protocols/dnp3/main.zeek 78 85

   :Type: :zeek:type:`Conn::RemovalHook`

   DNP3 finalization hook.  Remaining DNP3 info may get logged when it's called.

.. zeek:id:: DNP3::log_policy
   :source-code: base/protocols/dnp3/main.zeek 11 11

   :Type: :zeek:type:`Log::PolicyHook`



