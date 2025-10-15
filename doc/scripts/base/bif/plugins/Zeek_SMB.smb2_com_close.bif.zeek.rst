:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb2_com_close.bif.zeek
=================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================== ===========================================================================================
:zeek:id:`smb2_close_request`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                   version 2 requests of type *close*.
:zeek:id:`smb2_close_response`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                   version 2 responses of type *close*.
================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb2_close_request
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_close.bif.zeek 17 17

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *close*. This is used by the client to close an instance of a
   file that was opened previously with a successful SMB2 CREATE Request.
   
   For more information, see MS-SMB2:2.2.15
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_name: The SMB2 GUID of the file being closed.
   
   .. zeek:see:: smb2_message smb2_close_response

.. zeek:id:: smb2_close_response
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_close.bif.zeek 33 33

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, response: :zeek:type:`SMB2::CloseResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *close*. This is sent by the server to indicate that an SMB2 CLOSE
   request was processed successfully.
   
   For more information, see MS-SMB2:2.2.16
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param response: A record of attributes returned from the server from the close.
   
   .. zeek:see:: smb2_message smb2_close_request


