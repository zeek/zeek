:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb1_com_negotiate.bif.zeek
=====================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
====================================================== ===========================================================================================
:zeek:id:`smb1_negotiate_request`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                       version 1 requests of type *negotiate*.
:zeek:id:`smb1_negotiate_response`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                       version 1 responses of type *negotiate*.
====================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb1_negotiate_request
   :source-code: base/protocols/smb/smb1-main.zeek 77 80

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, dialects: :zeek:type:`string_vec`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *negotiate*. This is sent by the client to initiate an SMB
   connection between the client and the server. A *negotiate* exchange MUST be completed
   before any other SMB messages are sent to the server.
   
   For more information, see MS-CIFS:2.2.4.52
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param dialects: The SMB dialects supported by the client.
   
   .. zeek:see:: smb1_message smb1_negotiate_response

.. zeek:id:: smb1_negotiate_response
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_negotiate.bif.zeek 34 34

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, response: :zeek:type:`SMB1::NegotiateResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *negotiate*. This is the server response to the *negotiate*
   request.
   
   For more information, see MS-CIFS:2.2.4.52
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param response: A record structure containing more information from the response.
   
   .. zeek:see:: smb1_message smb1_negotiate_request


