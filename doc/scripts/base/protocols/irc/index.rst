:orphan:

Package: base/protocols/irc
===========================

Support for Internet Relay Chat (IRC) protocol analysis.

:doc:`/scripts/base/protocols/irc/__load__.zeek`


:doc:`/scripts/base/protocols/irc/main.zeek`

   Implements the core IRC analysis support.  The logging model is to log
   IRC commands along with the associated response and some additional
   metadata about the connection if it's available.

:doc:`/scripts/base/protocols/irc/dcc-send.zeek`

   File extraction and introspection for DCC transfers over IRC.
   
   There is a major problem with this script in the cluster context because
   we might see A send B a message that a DCC connection is to be expected,
   but that connection will actually be between B and C which could be
   analyzed on a different worker.
   

:doc:`/scripts/base/protocols/irc/files.zeek`


