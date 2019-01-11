:tocdepth: 3

base/bif/plugins/Bro_SMB.smb1_com_session_setup_andx.bif.bro
============================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================================= ===========================================================================================
:bro:id:`smb1_session_setup_andx_request`: :bro:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                              version 1 requests of type *setup andx*.
:bro:id:`smb1_session_setup_andx_response`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                              version 1 responses of type *setup andx*.
============================================================= ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb1_session_setup_andx_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, request: :bro:type:`SMB1::SessionSetupAndXRequest`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *setup andx*. This is sent by the client to configure an SMB session.
   
   For more information, see MS-CIFS:2.2.4.53
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :request: The parsed request data of the SMB message. See init-bare for more details.
   
   .. bro:see:: smb1_message smb1_session_setup_andx_response

.. bro:id:: smb1_session_setup_andx_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, response: :bro:type:`SMB1::SessionSetupAndXResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *setup andx*. This is the server response to the *setup andx* request.
   
   For more information, see MS-CIFS:2.2.4.53
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :response: The parsed response data of the SMB message. See init-bare for more details.
   
   .. bro:see:: smb1_message smb1_session_setup_andx_request


