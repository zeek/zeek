:tocdepth: 3

base/bif/plugins/Bro_SMB.smb2_com_negotiate.bif.bro
===================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
==================================================== ===========================================================================================
:bro:id:`smb2_negotiate_request`: :bro:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                     version 2 requests of type *negotiate*.
:bro:id:`smb2_negotiate_response`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                     version 2 responses of type *negotiate*.
==================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb2_negotiate_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, dialects: :bro:type:`index_vec`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *negotiate*. This is used by the client to notify the server what
   dialects of the SMB2 Protocol the client understands.
   
   For more information, see MS-SMB2:2.2.3
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :dialects: A vector of the client's supported dialects.
   
   .. bro:see:: smb2_message smb2_negotiate_response

.. bro:id:: smb2_negotiate_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, response: :bro:type:`SMB2::NegotiateResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *negotiate*. This is sent by the server to notify the client of
   the preferred common dialect.
   
   For more information, see MS-SMB2:2.2.4
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :response: The negotiate response data structure.
   
   .. bro:see:: smb2_message smb2_negotiate_request


