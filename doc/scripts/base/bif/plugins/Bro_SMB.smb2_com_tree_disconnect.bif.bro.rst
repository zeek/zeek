:tocdepth: 3

base/bif/plugins/Bro_SMB.smb2_com_tree_disconnect.bif.bro
=========================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================================== ===========================================================================================
:bro:id:`smb2_tree_disconnect_request`: :bro:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                           version 2 requests of type *tree disconnect*.
:bro:id:`smb2_tree_disconnect_response`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                           version 2 requests of type *tree disconnect*.
========================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb2_tree_disconnect_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *tree disconnect*. This is sent by the client to logically disconnect
   client access to a server resource.
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   
   .. bro:see:: smb2_message

.. bro:id:: smb2_tree_disconnect_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *tree disconnect*. This is sent by the server to logically disconnect
   client access to a server resource.
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   
   .. bro:see:: smb2_message


