:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb2_events.bif.zeek
==============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=========================================== ===========================================================================================
:zeek:id:`smb2_message`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                            version 2 messages.
=========================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb2_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, is_orig: :zeek:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Server_Message_Block>`__ for more information about the
   :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` protocol. Zeek's
   :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` analyzer parses
   both :abbr:`SMB (Server Message Block)`-over-:abbr:`NetBIOS (Network Basic Input/Output System)` on
   ports 138/139 and :abbr:`SMB (Server Message Block)`-over-TCP on port 445.
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :is_orig: True if the message came from the originator side.
   
   .. zeek:see:: smb1_message


