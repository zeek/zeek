:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb2_com_write.bif.zeek
=================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================== ===========================================================================================
:zeek:id:`smb2_write_request`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                   version 2 requests of type *write*.
:zeek:id:`smb2_write_response`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                   version 2 requests of type *write*.
================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb2_write_request
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_write.bif.zeek 21 21

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, offset: :zeek:type:`count`, length: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *write*. This is sent by the client to write data to the file or
   named pipe on the server.
   
   For more information, see MS-SMB2:2.2.21
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_id: The GUID being used for the file.
   

   :param offset: How far into the file this write should be taking place.
   

   :param length: The number of bytes of the file being written.
   
   .. zeek:see:: smb2_message

.. zeek:id:: smb2_write_response
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_write.bif.zeek 37 37

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, length: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *write*. This is sent by the server in response to a write request or
   named pipe on the server.
   
   For more information, see MS-SMB2:2.2.22
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param length: The number of bytes of the file being written.
   
   .. zeek:see:: smb2_message


