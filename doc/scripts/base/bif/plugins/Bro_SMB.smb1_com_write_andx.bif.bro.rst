:tocdepth: 3

base/bif/plugins/Bro_SMB.smb1_com_write_andx.bif.bro
====================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
===================================================== ===========================================================================================
:bro:id:`smb1_write_andx_request`: :bro:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                      version 1 requests of type *write andx*.
:bro:id:`smb1_write_andx_response`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                      version 1 responses of type *write andx*.
===================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb1_write_andx_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, file_id: :bro:type:`count`, offset: :bro:type:`count`, data_len: :bro:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *write andx*. This is sent by the client to write bytes to a
   regular file, a named pipe, or a directly accessible I/O device such as a serial port (COM)
   or printer port (LPT).
   
   For more information, see MS-CIFS:2.2.4.43
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :offset: The byte offset into the referenced file data is being written.
   

   :data: The data being written.
   
   .. bro:see:: smb1_message smb1_write_andx_response

.. bro:id:: smb1_write_andx_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, written_bytes: :bro:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *write andx*. This is the server response to the *write andx*
   request.
   
   For more information, see MS-CIFS:2.2.4.43
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :written_bytes: The number of bytes the server reported having actually written.
   
   .. bro:see:: smb1_message smb1_write_andx_request


