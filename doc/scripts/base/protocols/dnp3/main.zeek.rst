:tocdepth: 3

base/protocols/dnp3/main.zeek
=============================
.. zeek:namespace:: DNP3

A very basic DNP3 analysis script that just logs requests and replies.

:Namespace: DNP3
:Imports: :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/dnp3/consts.zeek </scripts/base/protocols/dnp3/consts.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
============================================================ ==========================
:zeek:id:`DNP3::ports`: :zeek:type:`set` :zeek:attr:`&redef` Well-known ports for DNP3.
============================================================ ==========================

Types
#####
============================================ =
:zeek:type:`DNP3::Info`: :zeek:type:`record`
============================================ =

Redefinitions
#############
============================================ ======================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`

                                             * :zeek:enum:`DNP3::LOG`
:zeek:type:`connection`: :zeek:type:`record`

                                             :New Fields: :zeek:type:`connection`

                                               dnp3: :zeek:type:`DNP3::Info` :zeek:attr:`&optional`
============================================ ======================================================

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
Redefinable Options
###################
.. zeek:id:: DNP3::ports
   :source-code: base/protocols/dnp3/main.zeek 12 12

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            20000/udp,
            20000/tcp
         }


   Well-known ports for DNP3.

Types
#####
.. zeek:type:: DNP3::Info
   :source-code: base/protocols/dnp3/main.zeek 16 29

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Time of the request.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique identifier for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      Identifier for the connection.


   .. zeek:field:: fc_request :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The name of the function message in the request.


   .. zeek:field:: fc_reply :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The name of the function message in the reply.


   .. zeek:field:: iin :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      The response's "internal indication number".



Events
######
.. zeek:id:: DNP3::log_dnp3
   :source-code: base/protocols/dnp3/main.zeek 33 33

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
   :source-code: base/protocols/dnp3/main.zeek 14 14

   :Type: :zeek:type:`Log::PolicyHook`



