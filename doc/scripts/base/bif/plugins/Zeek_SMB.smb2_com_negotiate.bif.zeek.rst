:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb2_com_negotiate.bif.zeek
=====================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
====================================================== ===========================================================================================
:zeek:id:`smb2_negotiate_request`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                       version 2 requests of type *negotiate*.
:zeek:id:`smb2_negotiate_response`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                       version 2 responses of type *negotiate*.
====================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb2_negotiate_request
   :source-code: base/protocols/smb/smb2-main.zeek 83 86

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, dialects: :zeek:type:`index_vec`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *negotiate*. This is used by the client to notify the server what
   dialects of the SMB2 Protocol the client understands.
   
   For more information, see MS-SMB2:2.2.3
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param dialects: A vector of the client's supported dialects.
   
   .. zeek:see:: smb2_message smb2_negotiate_response

.. zeek:id:: smb2_negotiate_response
   :source-code: base/protocols/smb/smb2-main.zeek 88 102

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, response: :zeek:type:`SMB2::NegotiateResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *negotiate*. This is sent by the server to notify the client of
   the preferred common dialect.
   
   For more information, see MS-SMB2:2.2.4
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param response: The negotiate response data structure.
   
   .. zeek:see:: smb2_message smb2_negotiate_request


