:tocdepth: 3

base/bif/plugins/Zeek_SMB.events.bif.zeek
=========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================================== ==========================================================================
:zeek:id:`smb_discarded_dce_rpc_analyzers`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)` when the number of
                                                               :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
                                                               analyzers exceeds :zeek:see:`SMB::max_dce_rpc_analyzers`.
:zeek:id:`smb_pipe_connect_heuristic`: :zeek:type:`event`      Generated for :abbr:`SMB (Server Message Block)` connections when a
                                                               named pipe has been detected heuristically.
============================================================== ==========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb_discarded_dce_rpc_analyzers
   :source-code: base/protocols/dce-rpc/main.zeek 219 226

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for :abbr:`SMB (Server Message Block)` when the number of
   :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
   analyzers exceeds :zeek:see:`SMB::max_dce_rpc_analyzers`.
   Occurrence of this event may indicate traffic loss, traffic load-balancing
   issues or abnormal SMB protocol usage.
   

   :param c: The connection.
   

.. zeek:id:: smb_pipe_connect_heuristic
   :source-code: base/protocols/smb/main.zeek 243 247

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for :abbr:`SMB (Server Message Block)` connections when a
   named pipe has been detected heuristically.  The case when this comes
   up is when the drive mapping isn't seen so the analyzer is not able
   to determine whether to send the data to the files framework or to
   the DCE_RPC analyzer. This heuristic can be tuned by adding or
   removing "named pipe" names from the :zeek:see:`SMB::pipe_filenames`
   const.
   

   :param c: The connection.


