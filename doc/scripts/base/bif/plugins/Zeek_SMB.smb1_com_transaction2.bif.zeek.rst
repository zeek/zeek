:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb1_com_transaction2.bif.zeek
========================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=================================================================== ===========================================================================================
:zeek:id:`smb1_trans2_find_first2_request`: :zeek:type:`event`      Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                                    version 1 *transaction2* requests of subtype *find first2*.
:zeek:id:`smb1_trans2_get_dfs_referral_request`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                                    version 1 *transaction2* requests of subtype *get DFS referral*.
:zeek:id:`smb1_trans2_query_path_info_request`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                                    version 1 *transaction2* requests of subtype *query path info*.
:zeek:id:`smb1_transaction2_request`: :zeek:type:`event`            Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                                    version 1 requests of type *transaction2*.
=================================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb1_trans2_find_first2_request
   :source-code: base/protocols/smb/smb1-main.zeek 247 250

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, args: :zeek:type:`SMB1::Find_First2_Request_Args`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 *transaction2* requests of subtype *find first2*. This transaction is used to begin
   a search for file(s) within a directory or for a directory
   
   For more information, see MS-CIFS:2.2.6.2
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param args: A record data structure with arguments given to the command.
   
   .. zeek:see:: smb1_message smb1_transaction2_request smb1_trans2_query_path_info_request
      smb1_trans2_get_dfs_referral_request

.. zeek:id:: smb1_trans2_get_dfs_referral_request
   :source-code: base/protocols/smb/smb1-main.zeek 237 240

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, file_name: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 *transaction2* requests of subtype *get DFS referral*. This transaction is used
   to request a referral for a disk object in DFS.
   
   For more information, see MS-CIFS:2.2.6.16
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param file_name: File name the request is in reference to.
   
   .. zeek:see:: smb1_message smb1_transaction2_request smb1_trans2_find_first2_request
      smb1_trans2_query_path_info_request

.. zeek:id:: smb1_trans2_query_path_info_request
   :source-code: base/protocols/smb/smb1-main.zeek 242 245

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, file_name: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 *transaction2* requests of subtype *query path info*. This transaction is used to
   get information about a specific file or directory.
   
   For more information, see MS-CIFS:2.2.6.6
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param file_name: File name the request is in reference to. 
   
   .. zeek:see:: smb1_message smb1_transaction2_request smb1_trans2_find_first2_request
      smb1_trans2_get_dfs_referral_request

.. zeek:id:: smb1_transaction2_request
   :source-code: base/protocols/smb/smb1-main.zeek 71 74

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, args: :zeek:type:`SMB1::Trans2_Args`, sub_cmd: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *transaction2*. This command serves as the transport for the
   Transaction2 Subprotocol Commands. These commands operate on mailslots and named pipes,
   which are interprocess communication endpoints within the CIFS file system. Compared to the
   Transaction Subprotocol Commands, these commands allow clients to set and retrieve Extended
   Attribute key/value pairs, make use of long file names (longer than the original 8.3 format
   names), and perform directory searches, among other tasks.
   
   For more information, see MS-CIFS:2.2.4.46
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param sub_cmd: The sub command, some are parsed and have their own events.
   
   .. zeek:see:: smb1_message smb1_trans2_find_first2_request smb1_trans2_query_path_info_request
      smb1_trans2_get_dfs_referral_request smb1_transaction_request


