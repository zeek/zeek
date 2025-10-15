:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb1_com_read_andx.bif.zeek
=====================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
====================================================== ===========================================================================================
:zeek:id:`smb1_read_andx_request`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                       version 1 requests of type *read andx*.
:zeek:id:`smb1_read_andx_response`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                       version 1 responses of type *read andx*.
====================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb1_read_andx_request
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_read_andx.bif.zeek 22 22

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, file_id: :zeek:type:`count`, offset: :zeek:type:`count`, length: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *read andx*. This is sent by the client to read bytes from a regular
   file, a named pipe, or a directly accessible device such as a serial port (COM) or printer
   port (LPT).
   
   For more information, see MS-CIFS:2.2.4.42
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param file_id: The file identifier being written to.
   

   :param offset: The byte offset the requested read begins at.
   

   :param length: The number of bytes being requested.
   
   .. zeek:see:: smb1_message smb1_read_andx_response

.. zeek:id:: smb1_read_andx_response
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_read_andx.bif.zeek 37 37

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, data_len: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *read andx*. This is the server response to the *read andx* request.
   
   For more information, see MS-CIFS:2.2.4.42
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param data_len: The length of data from the requested file.
   
   .. zeek:see:: smb1_message smb1_read_andx_request


