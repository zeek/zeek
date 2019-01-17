:tocdepth: 3

base/bif/plugins/Bro_SMB.events.bif.bro
=======================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================================= ===================================================================
:bro:id:`smb_pipe_connect_heuristic`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)` connections when a
                                                        named pipe has been detected heuristically.
======================================================= ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb_pipe_connect_heuristic

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated for :abbr:`SMB (Server Message Block)` connections when a
   named pipe has been detected heuristically.  The case when this comes
   up is when the drive mapping isn't seen so the analyzer is not able
   to determine whether to send the data to the files framework or to
   the DCE_RPC analyzer. This heuristic can be tuned by adding or
   removing "named pipe" names from the :bro:see:`SMB::pipe_filenames`
   const.
   

   :c: The connection.


