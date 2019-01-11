:tocdepth: 3

base/bif/plugins/Bro_SMB.smb2_com_write.bif.bro
===============================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=============================================== ===========================================================================================
:bro:id:`smb2_write_request`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                version 2 requests of type *write*.
=============================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb2_write_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, file_id: :bro:type:`SMB2::GUID`, offset: :bro:type:`count`, length: :bro:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *write*. This is sent by the client to write data to the file or
   named pipe on the server.
   
   For more information, see MS-SMB2:2.2.21
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The GUID being used for the file.
   

   :offset: How far into the file this write should be taking place.
   

   :length: The number of bytes of the file being written.
   
   .. bro:see:: smb2_message


