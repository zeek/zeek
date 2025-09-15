:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb1_com_transaction.bif.zeek
=======================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================================== ===========================================================================================
:zeek:id:`smb1_transaction_request`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                         version 1 requests of type *transaction*.
:zeek:id:`smb1_transaction_response`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                         version 1 requests of type *transaction*.
======================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb1_transaction_request
   :source-code: base/protocols/smb/smb1-main.zeek 262 265

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, name: :zeek:type:`string`, sub_cmd: :zeek:type:`count`, parameters: :zeek:type:`string`, data: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *transaction*. This command serves as the transport for the
   Transaction Subprotocol Commands. These commands operate on mailslots and named pipes,
   which are interprocess communication endpoints within the CIFS file system.
   
   For more information, see MS-CIFS:2.2.4.33.1
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param name: A name string that MAY identify the resource (a specific Mailslot or Named Pipe) 
         against which the operation is performed.
   

   :param sub_cmd: The sub command, some may be parsed and have their own events.
   

   :param parameters: content of the SMB_Data.Trans_Parameters field
   

   :param data: content of the SMB_Data.Trans_Data field
   
   .. zeek:see:: smb1_message smb1_transaction2_request

.. zeek:id:: smb1_transaction_response
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_transaction.bif.zeek 42 42

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, parameters: :zeek:type:`string`, data: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *transaction*. This command serves as the transport for the
   Transaction Subprotocol Commands. These commands operate on mailslots and named pipes,
   which are interprocess communication endpoints within the CIFS file system.
   
   For more information, see MS-CIFS:2.2.4.33.2
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param parameters: content of the SMB_Data.Trans_Parameters field
   

   :param data: content of the SMB_Data.Trans_Data field


