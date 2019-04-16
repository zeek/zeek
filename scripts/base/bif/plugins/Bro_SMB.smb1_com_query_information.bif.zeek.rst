:tocdepth: 3

base/bif/plugins/Bro_SMB.smb1_com_query_information.bif.zeek
============================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=========================================================== ===========================================================================================
:bro:id:`smb1_query_information_request`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                            version 1 requests of type *query information*.
=========================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb1_query_information_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, filename: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *query information*. This is a deprecated command which
   has been replaced by the *trans2_query_path_information* subcommand. This is used by the
   client to obtain attribute information about a file.
   
   For more information, see MS-CIFS:2.2.4.9
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :filename: The filename that the client is querying.
   
   .. bro:see:: smb1_message smb1_transaction2_request


