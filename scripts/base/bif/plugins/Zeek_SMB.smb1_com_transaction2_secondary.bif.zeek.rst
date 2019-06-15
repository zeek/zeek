:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb1_com_transaction2_secondary.bif.zeek
==================================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================================== ===========================================================================================
:zeek:id:`smb1_transaction2_secondary_request`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                                   version 1 requests of type *transaction2 secondary*.
================================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb1_transaction2_secondary_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, args: :zeek:type:`SMB1::Trans2_Sec_Args`, parameters: :zeek:type:`string`, data: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *transaction2 secondary*.
   
   For more information, see MS-CIFS:2.2.4.47.1
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)`
        version 1 message.
   

   :args: arguments of the message (SMB_Parameters.Words)
   

   :parameters: content of the SMB_Data.Trans_Parameters field
   

   :data: content of the SMB_Data.Trans_Data field


