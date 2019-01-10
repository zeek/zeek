:tocdepth: 3

base/bif/plugins/Bro_SMB.smb2_com_set_info.bif.bro
==================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================= ===========================================================================================
:bro:id:`smb2_file_delete`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                              version 2 requests of type *set_info* of the *delete* subtype.
:bro:id:`smb2_file_rename`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                              version 2 requests of type *set_info* of the *rename* subtype.
:bro:id:`smb2_file_sattr`: :bro:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                              version 2 requests of type *set_info* of the *file* subtype
============================================= ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb2_file_delete

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, file_id: :bro:type:`SMB2::GUID`, delete_pending: :bro:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *delete* subtype.
   
   For more information, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :delete_pending: A boolean value to indicate that a file should be deleted 
                   when it's closed if set to T.
   
   .. bro:see:: smb2_message smb2_file_rename smb2_file_sattr

.. bro:id:: smb2_file_rename

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, file_id: :bro:type:`SMB2::GUID`, dst_filename: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *rename* subtype.
   
   For more information, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: A GUID to identify the file.
   

   :dst_filename: The filename to rename the file into.
   
   .. bro:see:: smb2_message smb2_file_delete smb2_file_sattr

.. bro:id:: smb2_file_sattr

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, file_id: :bro:type:`SMB2::GUID`, times: :bro:type:`SMB::MACTimes`, attrs: :bro:type:`SMB2::FileAttrs`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *file* subtype
   
   For more infomation, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :times: Timestamps associated with the file in question.
   

   :attrs: File attributes.
   
   .. bro:see:: smb2_message smb2_file_rename smb2_file_delete


