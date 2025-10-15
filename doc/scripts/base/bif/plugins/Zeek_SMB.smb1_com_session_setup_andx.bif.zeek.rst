:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb1_com_session_setup_andx.bif.zeek
==============================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=============================================================== ===========================================================================================
:zeek:id:`smb1_session_setup_andx_request`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                                version 1 requests of type *setup andx*.
:zeek:id:`smb1_session_setup_andx_response`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                                version 1 responses of type *setup andx*.
=============================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb1_session_setup_andx_request
   :source-code: base/protocols/smb/smb1-main.zeek 252 253

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, request: :zeek:type:`SMB1::SessionSetupAndXRequest`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *setup andx*. This is sent by the client to configure an SMB session.
   
   For more information, see MS-CIFS:2.2.4.53
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param request: The parsed request data of the SMB message. See init-bare for more details.
   
   .. zeek:see:: smb1_message smb1_session_setup_andx_response

.. zeek:id:: smb1_session_setup_andx_response
   :source-code: base/protocols/smb/smb1-main.zeek 257 258

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, response: :zeek:type:`SMB1::SessionSetupAndXResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *setup andx*. This is the server response to the *setup andx* request.
   
   For more information, see MS-CIFS:2.2.4.53
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param response: The parsed response data of the SMB message. See init-bare for more details.
   
   .. zeek:see:: smb1_message smb1_session_setup_andx_request


