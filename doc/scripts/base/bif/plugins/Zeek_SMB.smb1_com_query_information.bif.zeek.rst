:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb1_com_query_information.bif.zeek
=============================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================================= ===========================================================================================
:zeek:id:`smb1_query_information_request`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                              version 1 requests of type *query information*.
============================================================= ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb1_query_information_request
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_query_information.bif.zeek 18 18

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, filename: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *query information*. This is a deprecated command which
   has been replaced by the *trans2_query_path_information* subcommand. This is used by the
   client to obtain attribute information about a file.
   
   For more information, see MS-CIFS:2.2.4.9
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param filename: The filename that the client is querying.
   
   .. zeek:see:: smb1_message smb1_transaction2_request


