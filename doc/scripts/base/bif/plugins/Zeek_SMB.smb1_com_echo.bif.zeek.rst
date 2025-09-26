:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb1_com_echo.bif.zeek
================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================= ===========================================================================================
:zeek:id:`smb1_echo_request`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                  version 1 requests of type *echo*.
:zeek:id:`smb1_echo_response`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                  version 1 responses of type *echo*.
================================================= ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb1_echo_request
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_echo.bif.zeek 19 19

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, echo_count: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *echo*. This is sent by the client to test the transport layer
   connection with the server.
   
   For more information, see MS-CIFS:2.2.4.39
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param echo_count: The number of times the server should echo the data back.
   

   :param data: The data for the server to echo.
   
   .. zeek:see:: smb1_message smb1_echo_response

.. zeek:id:: smb1_echo_response
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_echo.bif.zeek 36 36

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, seq_num: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *echo*. This is the server response to the *echo* request.
   
   For more information, see MS-CIFS:2.2.4.39
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param seq_num: The sequence number of this echo reply.
   

   :param data: The data echoed back from the client.
   
   .. zeek:see:: smb1_message smb1_echo_request


