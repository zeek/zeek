:tocdepth: 3

base/protocols/irc/dcc-send.zeek
================================
.. zeek:namespace:: IRC

File extraction and introspection for DCC transfers over IRC.

There is a major problem with this script in the cluster context because
we might see A send B a message that a DCC connection is to be expected,
but that connection will actually be between B and C which could be
analyzed on a different worker.


:Namespace: IRC
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/irc/main.zeek </scripts/base/protocols/irc/main.zeek>`, :doc:`base/utils/files.zeek </scripts/base/utils/files.zeek>`

Summary
~~~~~~~
Redefinitions
#############
=========================================== =============================================================================
:zeek:type:`IRC::Info`: :zeek:type:`record` 
                                            
                                            :New Fields: :zeek:type:`IRC::Info`
                                            
                                              dcc_file_name: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                DCC filename requested.
                                            
                                              dcc_file_size: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Size of the DCC transfer as indicated by the sender.
                                            
                                              dcc_mime_type: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Sniffed mime type of the file.
=========================================== =============================================================================

Hooks
#####
================================================================= ===============================
:zeek:id:`IRC::finalize_irc_data`: :zeek:type:`Conn::RemovalHook` IRC DCC data finalization hook.
================================================================= ===============================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Hooks
#####
.. zeek:id:: IRC::finalize_irc_data
   :source-code: base/protocols/irc/dcc-send.zeek 135 146

   :Type: :zeek:type:`Conn::RemovalHook`

   IRC DCC data finalization hook.  Remaining expected IRC DCC state may be
   purged when it's called.


