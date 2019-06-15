:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb1_com_nt_cancel.bif.zeek
=====================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
===================================================== ===========================================================================================
:zeek:id:`smb1_nt_cancel_request`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                      version 1 requests of type *nt cancel*.
===================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb1_nt_cancel_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *nt cancel*. This is sent by the client to request that a currently
   pending request be cancelled.
   
   For more information, see MS-CIFS:2.2.4.65
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   
   .. zeek:see:: smb1_message


