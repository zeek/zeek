:tocdepth: 3

base/bif/plugins/Bro_SMB.smb1_com_transaction.bif.bro
=====================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
====================================================== ===========================================================================================
:bro:id:`smb1_transaction_request`: :bro:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                       version 1 requests of type *transaction*.
:bro:id:`smb1_transaction_response`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                       version 1 requests of type *transaction*.
====================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb1_transaction_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, name: :bro:type:`string`, sub_cmd: :bro:type:`count`, parameters: :bro:type:`string`, data: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *transaction*. This command serves as the transport for the
   Transaction Subprotocol Commands. These commands operate on mailslots and named pipes,
   which are interprocess communication endpoints within the CIFS file system.
   
   For more information, see MS-CIFS:2.2.4.33.1
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :name: A name string that MAY identify the resource (a specific Mailslot or Named Pipe) 
         against which the operation is performed.
   

   :sub_cmd: The sub command, some may be parsed and have their own events.
   

   :parameters: content of the SMB_Data.Trans_Parameters field
   

   :data: content of the SMB_Data.Trans_Data field
   
   .. bro:see:: smb1_message smb1_transaction2_request

.. bro:id:: smb1_transaction_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, parameters: :bro:type:`string`, data: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *transaction*. This command serves as the transport for the
   Transaction Subprotocol Commands. These commands operate on mailslots and named pipes,
   which are interprocess communication endpoints within the CIFS file system.
   
   For more information, see MS-CIFS:2.2.4.33.2
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :parameters: content of the SMB_Data.Trans_Parameters field
   

   :data: content of the SMB_Data.Trans_Data field


