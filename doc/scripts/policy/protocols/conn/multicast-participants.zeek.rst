:tocdepth: 3

policy/protocols/conn/multicast-participants.zeek
=================================================
.. zeek:namespace:: Conn


:Namespace: Conn
:Imports: :doc:`base/packet-protocols/igmp/types.zeek </scripts/base/packet-protocols/igmp/types.zeek>`, :doc:`base/protocols/conn </scripts/base/protocols/conn/index>`

Summary
~~~~~~~
Types
#####
================================================================= =
:zeek:type:`Conn::MulticastParticipantsInfo`: :zeek:type:`record`
================================================================= =

Redefinitions
#############
============================================ =============================================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`

                                             * :zeek:enum:`Conn::MULTICAST_PARTICIPANTS_LOG`
:zeek:type:`connection`: :zeek:type:`record`

                                             :New Fields: :zeek:type:`connection`

                                               multicast_srcs: :zeek:type:`set` [:zeek:type:`addr`] :zeek:attr:`&optional`
============================================ =============================================================================

Events
######
================================================== ===============================================================
:zeek:id:`Conn::log_multicast`: :zeek:type:`event` Event that can be handled to access the :zeek:type:`Conn::Info`
                                                   record as it is sent on to the logging framework.
================================================== ===============================================================

Hooks
#####
=================================================================== =
:zeek:id:`Conn::log_policy_multicast`: :zeek:type:`Log::PolicyHook`
=================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Conn::MulticastParticipantsInfo
   :source-code: policy/protocols/conn/multicast-participants.zeek 14 21

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`


   .. zeek:field:: cid :zeek:type:`string` :zeek:attr:`&log`


   .. zeek:field:: orig_h :zeek:type:`addr` :zeek:attr:`&log`


   .. zeek:field:: multicast_addr :zeek:type:`addr` :zeek:attr:`&log`


   .. zeek:field:: multicast_p :zeek:type:`port` :zeek:attr:`&log`


   .. zeek:field:: participants :zeek:type:`set` [:zeek:type:`addr`] :zeek:attr:`&log`



Events
######
.. zeek:id:: Conn::log_multicast
   :source-code: policy/protocols/conn/multicast-participants.zeek 25 25

   :Type: :zeek:type:`event` (rec: :zeek:type:`Conn::MulticastParticipantsInfo`)

   Event that can be handled to access the :zeek:type:`Conn::Info`
   record as it is sent on to the logging framework.

Hooks
#####
.. zeek:id:: Conn::log_policy_multicast
   :source-code: policy/protocols/conn/multicast-participants.zeek 12 12

   :Type: :zeek:type:`Log::PolicyHook`



