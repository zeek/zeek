:tocdepth: 3

base/protocols/irc/dcc-send.zeek
================================
.. bro:namespace:: IRC

File extraction and introspection for DCC transfers over IRC.

There is a major problem with this script in the cluster context because
we might see A send B a message that a DCC connection is to be expected,
but that connection will actually be between B and C which could be
analyzed on a different worker.


:Namespace: IRC
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/protocols/irc/main.zeek </scripts/base/protocols/irc/main.zeek>`, :doc:`base/utils/files.zeek </scripts/base/utils/files.zeek>`

Summary
~~~~~~~
Redefinitions
#############
========================================= =
:bro:type:`IRC::Info`: :bro:type:`record` 
========================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~

