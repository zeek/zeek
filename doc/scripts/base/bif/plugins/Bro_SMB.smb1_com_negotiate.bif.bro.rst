:tocdepth: 3

base/bif/plugins/Bro_SMB.smb1_com_negotiate.bif.bro
===================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
==================================================== ===========================================================================================
:bro:id:`smb1_negotiate_request`: :bro:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                     version 1 requests of type *negotiate*.
:bro:id:`smb1_negotiate_response`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                     version 1 responses of type *negotiate*.
==================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb1_negotiate_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, dialects: :bro:type:`string_vec`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *negotiate*. This is sent by the client to initiate an SMB
   connection between the client and the server. A *negotiate* exchange MUST be completed
   before any other SMB messages are sent to the server.
   
   For more information, see MS-CIFS:2.2.4.52
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :dialects: The SMB dialects supported by the client.
   
   .. bro:see:: smb1_message smb1_negotiate_response

.. bro:id:: smb1_negotiate_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, response: :bro:type:`SMB1::NegotiateResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *negotiate*. This is the server response to the *negotiate*
   request.
   
   For more information, see MS-CIFS:2.2.4.52
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :response: A record structure containing more information from the response.
   
   .. bro:see:: smb1_message smb1_negotiate_request


