:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb2_com_tree_connect.bif.zeek
========================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================================= ===========================================================================================
:zeek:id:`smb2_tree_connect_request`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                          version 2 requests of type *tree_connect*.
:zeek:id:`smb2_tree_connect_response`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                          version 2 responses of type *tree_connect*.
========================================================= ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb2_tree_connect_request
   :source-code: base/protocols/smb/smb2-main.zeek 104 107

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, path: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *tree_connect*. This is sent by a client to request access to a
   particular share on the server.
   
   For more information, see MS-SMB2:2.2.9
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param path: Path of the requested tree.
   
   .. zeek:see:: smb2_message smb2_tree_connect_response

.. zeek:id:: smb2_tree_connect_response
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_tree_connect.bif.zeek 33 33

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, response: :zeek:type:`SMB2::TreeConnectResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *tree_connect*. This is sent by the server when a *tree_connect*
   request is successfully processed by the server.
   
   For more information, see MS-SMB2:2.2.10
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param response: A record with more information related to the response.
   
   .. zeek:see:: smb2_message smb2_tree_connect_request


