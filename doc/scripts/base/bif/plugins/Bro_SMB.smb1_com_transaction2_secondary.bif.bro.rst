:tocdepth: 3

base/bif/plugins/Bro_SMB.smb1_com_transaction2_secondary.bif.bro
================================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================================ ===========================================================================================
:bro:id:`smb1_transaction2_secondary_request`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                                 version 1 requests of type *transaction2 secondary*.
================================================================ ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb1_transaction2_secondary_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, args: :bro:type:`SMB1::Trans2_Sec_Args`, parameters: :bro:type:`string`, data: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *transaction2 secondary*.
   
   For more information, see MS-CIFS:2.2.4.47.1
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)`
        version 1 message.
   

   :args: arguments of the message (SMB_Parameters.Words)
   

   :parameters: content of the SMB_Data.Trans_Parameters field
   

   :data: content of the SMB_Data.Trans_Data field


