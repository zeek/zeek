:tocdepth: 3

base/bif/plugins/Bro_SMB.smb2_events.bif.bro
============================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================= ===========================================================================================
:bro:id:`smb2_message`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                          version 2 messages.
========================================= ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb2_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, is_orig: :bro:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Server_Message_Block>`__ for more information about the
   :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` protocol. Bro's
   :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` analyzer parses
   both :abbr:`SMB (Server Message Block)`-over-:abbr:`NetBIOS (Network Basic Input/Output System)` on
   ports 138/139 and :abbr:`SMB (Server Message Block)`-over-TCP on port 445.
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :is_orig: True if the message came from the originator side.
   
   .. bro:see:: smb1_message


