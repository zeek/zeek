:tocdepth: 3

base/bif/plugins/Bro_SMB.smb2_com_close.bif.zeek
================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================ ===========================================================================================
:bro:id:`smb2_close_request`: :bro:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                 version 2 requests of type *close*.
:bro:id:`smb2_close_response`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                 version 2 responses of type *close*.
================================================ ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb2_close_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, file_id: :bro:type:`SMB2::GUID`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *close*. This is used by the client to close an instance of a
   file that was opened previously with a successful SMB2 CREATE Request.
   
   For more information, see MS-SMB2:2.2.15
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_name: The SMB2 GUID of the file being closed.
   
   .. bro:see:: smb2_message smb2_close_response

.. bro:id:: smb2_close_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, response: :bro:type:`SMB2::CloseResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *close*. This is sent by the server to indicate that an SMB2 CLOSE
   request was processed successfully.
   
   For more information, see MS-SMB2:2.2.16
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :response: A record of attributes returned from the server from the close.
   
   .. bro:see:: smb2_message smb2_close_request


