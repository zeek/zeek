:tocdepth: 3

base/bif/plugins/Bro_SMB.smb2_com_session_setup.bif.zeek
========================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================================== ===========================================================================================
:bro:id:`smb2_session_setup_request`: :bro:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                         version 2 requests of type *session_setup*.
:bro:id:`smb2_session_setup_response`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                         version 2 responses of type *session_setup*.
======================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb2_session_setup_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, request: :bro:type:`SMB2::SessionSetupRequest`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *session_setup*. This is sent by the client to request a new
   authenticated session within a new or existing SMB 2 Protocol transport connection to the
   server.
   
   For more information, see MS-SMB2:2.2.5
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :request: A record containing more information related to the request.
   
   .. bro:see:: smb2_message smb2_session_setup_response

.. bro:id:: smb2_session_setup_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, response: :bro:type:`SMB2::SessionSetupResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *session_setup*. This is sent by the server in response to a
   *session_setup* request.
   
   For more information, see MS-SMB2:2.2.6
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :response: A record containing more information related to the response.
   
   .. bro:see:: smb2_message smb2_session_setup_request


