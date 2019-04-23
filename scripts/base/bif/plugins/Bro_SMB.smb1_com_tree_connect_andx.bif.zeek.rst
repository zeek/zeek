:tocdepth: 3

base/bif/plugins/Bro_SMB.smb1_com_tree_connect_andx.bif.zeek
============================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================================== ===========================================================================================
:zeek:id:`smb1_tree_connect_andx_request`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                               version 1 requests of type *tree connect andx*.
:zeek:id:`smb1_tree_connect_andx_response`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                               version 1 responses of type *tree connect andx*.
============================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb1_tree_connect_andx_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, path: :zeek:type:`string`, service: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *tree connect andx*. This is sent by the client to establish a
   connection to a server share.
   
   For more information, see MS-CIFS:2.2.4.55
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :path: The ``path`` attribute specified in the message.
   

   :service: The ``service`` attribute specified in the message.
   
   .. zeek:see:: smb1_message smb1_tree_connect_andx_response

.. zeek:id:: smb1_tree_connect_andx_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, service: :zeek:type:`string`, native_file_system: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *tree connect andx*. This is the server reply to the *tree connect andx*
   request.
   
   For more information, see MS-CIFS:2.2.4.55
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :service: The ``service`` attribute specified in the message.
   

   :native_file_system: The file system of the remote server as indicate by the server.
   
   .. zeek:see:: smb1_message smb1_tree_connect_andx_request


