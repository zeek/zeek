:tocdepth: 3

base/bif/plugins/Bro_SMB.smb2_com_set_info.bif.zeek
===================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=============================================== ===========================================================================================
:zeek:id:`smb2_file_delete`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                version 2 requests of type *set_info* of the *delete* subtype.
:zeek:id:`smb2_file_rename`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                version 2 requests of type *set_info* of the *rename* subtype.
:zeek:id:`smb2_file_sattr`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                version 2 requests of type *set_info* of the *file* subtype
=============================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb2_file_delete

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, delete_pending: :zeek:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *delete* subtype.
   
   For more information, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :delete_pending: A boolean value to indicate that a file should be deleted 
                   when it's closed if set to T.
   
   .. zeek:see:: smb2_message smb2_file_rename smb2_file_sattr

.. zeek:id:: smb2_file_rename

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, dst_filename: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *rename* subtype.
   
   For more information, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: A GUID to identify the file.
   

   :dst_filename: The filename to rename the file into.
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr

.. zeek:id:: smb2_file_sattr

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, times: :zeek:type:`SMB::MACTimes`, attrs: :zeek:type:`SMB2::FileAttrs`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *file* subtype
   
   For more infomation, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :times: Timestamps associated with the file in question.
   

   :attrs: File attributes.
   
   .. zeek:see:: smb2_message smb2_file_rename smb2_file_delete


