:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb1_com_logoff_andx.bif.zeek
=======================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=============================================== ===========================================================================================
:zeek:id:`smb1_logoff_andx`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                version 1 requests of type *logoff andx*.
=============================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb1_logoff_andx
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_logoff_andx.bif.zeek 17 17

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *logoff andx*. This is used by the client to logoff the user
   connection represented by UID in the SMB Header. The server releases all locks and closes
   all files currently open by this user, disconnects all tree connects, cancels any outstanding
   requests for this UID, and invalidates the UID.
   
   For more information, see MS-CIFS:2.2.4.54
   

   :param c: The connection.
   

   :param is_orig: Indicates which host sent the logoff message.
   
   .. zeek:see:: smb1_message


