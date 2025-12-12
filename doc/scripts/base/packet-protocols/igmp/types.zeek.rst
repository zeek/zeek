:tocdepth: 3

base/packet-protocols/igmp/types.zeek
=====================================
.. zeek:namespace:: IGMP


:Namespace: IGMP

Summary
~~~~~~~
Types
#####
====================================================== =
:zeek:type:`IGMP::GroupType`: :zeek:type:`enum`        
:zeek:type:`IGMP::IgmpMessageType`: :zeek:type:`enum`  
:zeek:type:`IGMP::MulticastGroup`: :zeek:type:`record` 
====================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: IGMP::GroupType
   :source-code: base/packet-protocols/igmp/types.zeek 18 26

   :Type: :zeek:type:`enum`

      .. zeek:enum:: IGMP::MODE_IS_INCLUDE IGMP::GroupType

      .. zeek:enum:: IGMP::MODE_IS_EXCLUDE IGMP::GroupType

      .. zeek:enum:: IGMP::CHANGE_TO_INCLUDE_MODE IGMP::GroupType

      .. zeek:enum:: IGMP::CHANGE_TO_EXCLUDE_MODE IGMP::GroupType

      .. zeek:enum:: IGMP::ALLOW_NEW_SOURCES IGMP::GroupType

      .. zeek:enum:: IGMP::BLOCK_OLD_SOURCES IGMP::GroupType


.. zeek:type:: IGMP::IgmpMessageType
   :source-code: base/packet-protocols/igmp/types.zeek 8 16

   :Type: :zeek:type:`enum`

      .. zeek:enum:: IGMP::BAD_CHECKSUM IGMP::IgmpMessageType

      .. zeek:enum:: IGMP::MEMBERSHIP_QUERY IGMP::IgmpMessageType

      .. zeek:enum:: IGMP::MEMBERSHIP_REPORT_V1 IGMP::IgmpMessageType

      .. zeek:enum:: IGMP::MEMBERSHIP_REPORT_V2 IGMP::IgmpMessageType

      .. zeek:enum:: IGMP::LEAVE_GROUP IGMP::IgmpMessageType

      .. zeek:enum:: IGMP::MEMBERSHIP_REPORT_V3 IGMP::IgmpMessageType


.. zeek:type:: IGMP::MulticastGroup
   :source-code: base/packet-protocols/igmp/types.zeek 28 35

   :Type: :zeek:type:`record`


   .. zeek:field:: group_type :zeek:type:`IGMP::GroupType`


   .. zeek:field:: aux_data_len :zeek:type:`count`


   .. zeek:field:: num_sources :zeek:type:`count`


   .. zeek:field:: multicast_addr :zeek:type:`addr`


   .. zeek:field:: sources :zeek:type:`vector` of :zeek:type:`addr`


   .. zeek:field:: aux_data :zeek:type:`string`




