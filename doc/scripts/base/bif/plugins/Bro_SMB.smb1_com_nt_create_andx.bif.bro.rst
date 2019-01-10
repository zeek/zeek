:tocdepth: 3

base/bif/plugins/Bro_SMB.smb1_com_nt_create_andx.bif.bro
========================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================================= ===========================================================================================
:bro:id:`smb1_nt_create_andx_request`: :bro:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                          version 1 requests of type *nt create andx*.
:bro:id:`smb1_nt_create_andx_response`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                          version 1 responses of type *nt create andx*.
========================================================= ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb1_nt_create_andx_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, file_name: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *nt create andx*. This is sent by the client to create and open
   a new file, or to open an existing file, or to open and truncate an existing file to zero
   length, or to create a directory, or to create a connection to a named pipe.
   
   For more information, see MS-CIFS:2.2.4.64
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :name: The ``name`` attribute  specified in the message.
   
   .. bro:see:: smb1_message smb1_nt_create_andx_response

.. bro:id:: smb1_nt_create_andx_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, file_id: :bro:type:`count`, file_size: :bro:type:`count`, times: :bro:type:`SMB::MACTimes`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *nt create andx*. This is the server response to the
   *nt create andx* request.
   
   For more information, see MS-CIFS:2.2.4.64
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :file_size: Size of the file.
   

   :times: Timestamps associated with the file in question.
   
   .. bro:see:: smb1_message smb1_nt_create_andx_request


