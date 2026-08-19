:tocdepth: 3

policy/protocols/conn/multicast-participants.zeek
=================================================
.. zeek:namespace:: Conn


:Namespace: Conn
:Imports: :doc:`base/packet-protocols/igmp/types.zeek </scripts/base/packet-protocols/igmp/types.zeek>`, :doc:`base/protocols/conn </scripts/base/protocols/conn/index>`

Summary
~~~~~~~
Redefinable Options
###################
=================================================================================== =============================================================
:zeek:id:`Conn::max_igmp_groups`: :zeek:type:`count` :zeek:attr:`&redef`            The maximum number of IGMP groups that Zeek will track.
:zeek:id:`Conn::max_igmp_sources_per_group`: :zeek:type:`count` :zeek:attr:`&redef` The maximum number of IGMP sources Zeek will track per group.
=================================================================================== =============================================================

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
=================================================================== =============================================
:zeek:id:`Conn::log_policy_multicast`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
=================================================================== =============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Conn::max_igmp_groups
   :source-code: policy/protocols/conn/multicast-participants.zeek 43 43

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``500``

   The maximum number of IGMP groups that Zeek will track. If this limit is hit a
   ``igmp_max_groups_exceeded`` weird will be reported and new groups will be
   dropped and not tracked in the list of connections. Set this to zero to disable
   the limiting.

.. zeek:id:: Conn::max_igmp_sources_per_group
   :source-code: policy/protocols/conn/multicast-participants.zeek 49 49

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``500``

   The maximum number of IGMP sources Zeek will track per group. If this limit is
   hit a ``igmp_max_sources_exceeded`` weird will be reported and new sources
   for that group will be dropped and not tracked in the list of connections. Set
   this to zero to disable the limiting.

Types
#####
.. zeek:type:: Conn::MulticastParticipantsInfo
   :source-code: policy/protocols/conn/multicast-participants.zeek 17 33

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      The timestamp of the connection.


   .. zeek:field:: cid :zeek:type:`string` :zeek:attr:`&log`

      The UID string for the connection. This is the uid field from the
      original connection record.


   .. zeek:field:: orig_h :zeek:type:`addr` :zeek:attr:`&log`

      The address of the host origintating the connection to the multicast
      group address.


   .. zeek:field:: group_addr :zeek:type:`addr` :zeek:attr:`&log`

      The multicast group address for the connection.


   .. zeek:field:: group_p :zeek:type:`port` :zeek:attr:`&log`

      The port used in the multicast connection.


   .. zeek:field:: participants :zeek:type:`set` [:zeek:type:`addr`] :zeek:attr:`&log`

      The set of multicast participants collected from IGMP for the group
      address.



Events
######
.. zeek:id:: Conn::log_multicast
   :source-code: policy/protocols/conn/multicast-participants.zeek 37 37

   :Type: :zeek:type:`event` (rec: :zeek:type:`Conn::MulticastParticipantsInfo`)

   Event that can be handled to access the :zeek:type:`Conn::Info`
   record as it is sent on to the logging framework.

Hooks
#####
.. zeek:id:: Conn::log_policy_multicast
   :source-code: policy/protocols/conn/multicast-participants.zeek 13 13

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


