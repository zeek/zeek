:tocdepth: 3

base/bif/plugins/Bro_SMB.smb2_com_read.bif.zeek
===============================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================== ===========================================================================================
:bro:id:`smb2_read_request`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                               version 2 requests of type *read*.
============================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb2_read_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, file_id: :bro:type:`SMB2::GUID`, offset: :bro:type:`count`, length: :bro:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *read*. This is sent by the client to request a read operation on
   the specified file.
   
   For more information, see MS-SMB2:2.2.19
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The GUID being used for the file.
   

   :offset: How far into the file this read should be taking place.
   

   :length: The number of bytes of the file being read.
   
   .. bro:see:: smb2_message


