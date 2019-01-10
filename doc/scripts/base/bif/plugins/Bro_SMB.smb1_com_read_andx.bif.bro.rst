:tocdepth: 3

base/bif/plugins/Bro_SMB.smb1_com_read_andx.bif.bro
===================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
==================================================== ===========================================================================================
:bro:id:`smb1_read_andx_request`: :bro:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                     version 1 requests of type *read andx*.
:bro:id:`smb1_read_andx_response`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                     version 1 responses of type *read andx*.
==================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb1_read_andx_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, file_id: :bro:type:`count`, offset: :bro:type:`count`, length: :bro:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *read andx*. This is sent by the client to read bytes from a regular
   file, a named pipe, or a directly accessible device such as a serial port (COM) or printer
   port (LPT).
   
   For more information, see MS-CIFS:2.2.4.42
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :file_id: The file identifier being written to.
   

   :offset: The byte offset the requested read begins at.
   

   :length: The number of bytes being requested.
   
   .. bro:see:: smb1_message smb1_read_andx_response

.. bro:id:: smb1_read_andx_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, data_len: :bro:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *read andx*. This is the server response to the *read andx* request.
   
   For more information, see MS-CIFS:2.2.4.42
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :data_len: The length of data from the requested file.
   
   .. bro:see:: smb1_message smb1_read_andx_request


