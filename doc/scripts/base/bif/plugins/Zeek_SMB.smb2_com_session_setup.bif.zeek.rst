:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb2_com_session_setup.bif.zeek
=========================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================================== ===========================================================================================
:zeek:id:`smb2_session_setup_request`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                           version 2 requests of type *session_setup*.
:zeek:id:`smb2_session_setup_response`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                           version 2 responses of type *session_setup*.
========================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb2_session_setup_request
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_session_setup.bif.zeek 18 18

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, request: :zeek:type:`SMB2::SessionSetupRequest`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *session_setup*. This is sent by the client to request a new
   authenticated session within a new or existing SMB 2 Protocol transport connection to the
   server.
   
   For more information, see MS-SMB2:2.2.5
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param request: A record containing more information related to the request.
   
   .. zeek:see:: smb2_message smb2_session_setup_response

.. zeek:id:: smb2_session_setup_response
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_session_setup.bif.zeek 34 34

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, response: :zeek:type:`SMB2::SessionSetupResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *session_setup*. This is sent by the server in response to a
   *session_setup* request.
   
   For more information, see MS-SMB2:2.2.6
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param response: A record containing more information related to the response.
   
   .. zeek:see:: smb2_message smb2_session_setup_request


