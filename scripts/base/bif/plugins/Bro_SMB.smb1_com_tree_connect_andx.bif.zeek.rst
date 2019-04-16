:tocdepth: 3

base/bif/plugins/Bro_SMB.smb1_com_tree_connect_andx.bif.zeek
============================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================================ ===========================================================================================
:bro:id:`smb1_tree_connect_andx_request`: :bro:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                             version 1 requests of type *tree connect andx*.
:bro:id:`smb1_tree_connect_andx_response`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                             version 1 responses of type *tree connect andx*.
============================================================ ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb1_tree_connect_andx_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, path: :bro:type:`string`, service: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *tree connect andx*. This is sent by the client to establish a
   connection to a server share.
   
   For more information, see MS-CIFS:2.2.4.55
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :path: The ``path`` attribute specified in the message.
   

   :service: The ``service`` attribute specified in the message.
   
   .. bro:see:: smb1_message smb1_tree_connect_andx_response

.. bro:id:: smb1_tree_connect_andx_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, service: :bro:type:`string`, native_file_system: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *tree connect andx*. This is the server reply to the *tree connect andx*
   request.
   
   For more information, see MS-CIFS:2.2.4.55
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :service: The ``service`` attribute specified in the message.
   

   :native_file_system: The file system of the remote server as indicate by the server.
   
   .. bro:see:: smb1_message smb1_tree_connect_andx_request


