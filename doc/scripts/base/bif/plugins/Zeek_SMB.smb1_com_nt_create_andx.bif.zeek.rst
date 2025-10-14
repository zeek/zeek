:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb1_com_nt_create_andx.bif.zeek
==========================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=========================================================== ===========================================================================================
:zeek:id:`smb1_nt_create_andx_request`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                            version 1 requests of type *nt create andx*.
:zeek:id:`smb1_nt_create_andx_response`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                            version 1 responses of type *nt create andx*.
=========================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb1_nt_create_andx_request
   :source-code: base/protocols/smb/smb1-main.zeek 137 146

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, file_name: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *nt create andx*. This is sent by the client to create and open
   a new file, or to open an existing file, or to open and truncate an existing file to zero
   length, or to create a directory, or to create a connection to a named pipe.
   
   For more information, see MS-CIFS:2.2.4.64
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param name: The ``name`` attribute  specified in the message.
   
   .. zeek:see:: smb1_message smb1_nt_create_andx_response

.. zeek:id:: smb1_nt_create_andx_response
   :source-code: base/protocols/smb/smb1-main.zeek 148 165

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, file_id: :zeek:type:`count`, file_size: :zeek:type:`count`, times: :zeek:type:`SMB::MACTimes`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *nt create andx*. This is the server response to the
   *nt create andx* request.
   
   For more information, see MS-CIFS:2.2.4.64
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param file_id: The SMB2 GUID for the file.
   

   :param file_size: Size of the file.
   

   :param times: Timestamps associated with the file in question.
   
   .. zeek:see:: smb1_message smb1_nt_create_andx_request


