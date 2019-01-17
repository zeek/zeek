:tocdepth: 3

base/bif/plugins/Bro_SMB.smb1_com_echo.bif.bro
==============================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=============================================== ===========================================================================================
:bro:id:`smb1_echo_request`: :bro:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                version 1 requests of type *echo*.
:bro:id:`smb1_echo_response`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                version 1 responses of type *echo*.
=============================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb1_echo_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, echo_count: :bro:type:`count`, data: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *echo*. This is sent by the client to test the transport layer
   connection with the server.
   
   For more information, see MS-CIFS:2.2.4.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :echo_count: The number of times the server should echo the data back.
   

   :data: The data for the server to echo.
   
   .. bro:see:: smb1_message smb1_echo_response

.. bro:id:: smb1_echo_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, seq_num: :bro:type:`count`, data: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *echo*. This is the server response to the *echo* request.
   
   For more information, see MS-CIFS:2.2.4.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :seq_num: The sequence number of this echo reply.
   

   :data: The data echoed back from the client.
   
   .. bro:see:: smb1_message smb1_echo_request


