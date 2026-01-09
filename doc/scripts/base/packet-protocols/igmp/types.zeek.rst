:tocdepth: 3

base/packet-protocols/igmp/types.zeek
=====================================
.. zeek:namespace:: IGMP


:Namespace: IGMP

Summary
~~~~~~~
Types
#####
================================================= ==================================================================
:zeek:type:`IGMP::Group`: :zeek:type:`record`     IGMP Version 3 Membership Report Group record, as defined in
                                                  :rfc:`3376#section-4.2`
:zeek:type:`IGMP::GroupType`: :zeek:type:`enum`   IGMP Version 3 Membership Report Group record types, as defined in
                                                  :rfc:`3376#section-4.2.12`
:zeek:type:`IGMP::MessageType`: :zeek:type:`enum` Types used by the IGMP packet analyzer plugin
                                                  IGMP message types, as defined in :rfc:`3376#section-4`.
================================================= ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: IGMP::Group
   :source-code: base/packet-protocols/igmp/types.zeek 30 43

   :Type: :zeek:type:`record`


   .. zeek:field:: group_type :zeek:type:`IGMP::GroupType`

      The type of the multicast record being reported.


   .. zeek:field:: aux_data_len :zeek:type:`count`

      The length of the auxiliary data field in this group record.


   .. zeek:field:: num_sources :zeek:type:`count`

      The number of source addresses.


   .. zeek:field:: multicast_addr :zeek:type:`addr`

      The multicase address to which this record pertains.


   .. zeek:field:: sources :zeek:type:`vector` of :zeek:type:`addr`

      A vector of source addresses.


   .. zeek:field:: aux_data :zeek:type:`string`

      Additional information pertaining to this record.


   IGMP Version 3 Membership Report Group record, as defined in
   :rfc:`3376#section-4.2`

.. zeek:type:: IGMP::GroupType
   :source-code: base/packet-protocols/igmp/types.zeek 19 27

   :Type: :zeek:type:`enum`

      .. zeek:enum:: IGMP::MODE_IS_INCLUDE IGMP::GroupType

      .. zeek:enum:: IGMP::MODE_IS_EXCLUDE IGMP::GroupType

      .. zeek:enum:: IGMP::CHANGE_TO_INCLUDE_MODE IGMP::GroupType

      .. zeek:enum:: IGMP::CHANGE_TO_EXCLUDE_MODE IGMP::GroupType

      .. zeek:enum:: IGMP::ALLOW_NEW_SOURCES IGMP::GroupType

      .. zeek:enum:: IGMP::BLOCK_OLD_SOURCES IGMP::GroupType

   IGMP Version 3 Membership Report Group record types, as defined in
   :rfc:`3376#section-4.2.12`

.. zeek:type:: IGMP::MessageType
   :source-code: base/packet-protocols/igmp/types.zeek 8 16

   :Type: :zeek:type:`enum`

      .. zeek:enum:: IGMP::BAD_CHECKSUM IGMP::MessageType

      .. zeek:enum:: IGMP::MEMBERSHIP_QUERY IGMP::MessageType

      .. zeek:enum:: IGMP::MEMBERSHIP_REPORT_V1 IGMP::MessageType

      .. zeek:enum:: IGMP::MEMBERSHIP_REPORT_V2 IGMP::MessageType

      .. zeek:enum:: IGMP::LEAVE_GROUP IGMP::MessageType

      .. zeek:enum:: IGMP::MEMBERSHIP_REPORT_V3 IGMP::MessageType

   Types used by the IGMP packet analyzer plugin
   IGMP message types, as defined in :rfc:`3376#section-4`.


