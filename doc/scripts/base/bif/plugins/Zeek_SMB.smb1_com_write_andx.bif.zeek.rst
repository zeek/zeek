:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb1_com_write_andx.bif.zeek
======================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================================= ===========================================================================================
:zeek:id:`smb1_write_andx_request`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                        version 1 requests of type *write andx*.
:zeek:id:`smb1_write_andx_response`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                        version 1 responses of type *write andx*.
======================================================= ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb1_write_andx_request
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_write_andx.bif.zeek 20 20

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, file_id: :zeek:type:`count`, offset: :zeek:type:`count`, data_len: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *write andx*. This is sent by the client to write bytes to a
   regular file, a named pipe, or a directly accessible I/O device such as a serial port (COM)
   or printer port (LPT).
   
   For more information, see MS-CIFS:2.2.4.43
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param offset: The byte offset into the referenced file data is being written.
   

   :param data: The data being written.
   
   .. zeek:see:: smb1_message smb1_write_andx_response

.. zeek:id:: smb1_write_andx_response
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_write_andx.bif.zeek 36 36

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, written_bytes: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *write andx*. This is the server response to the *write andx*
   request.
   
   For more information, see MS-CIFS:2.2.4.43
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param written_bytes: The number of bytes the server reported having actually written.
   
   .. zeek:see:: smb1_message smb1_write_andx_request


