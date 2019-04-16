:orphan:

Package: base/protocols/xmpp
============================

Support for the Extensible Messaging and Presence Protocol (XMPP).

Note that currently the XMPP analyzer only supports analyzing XMPP sessions
until they do or do not switch to TLS using StartTLS. Hence, we do not get
actual chat information from XMPP sessions, only X509 certificates.

:doc:`/scripts/base/protocols/xmpp/__load__.zeek`


:doc:`/scripts/base/protocols/xmpp/main.zeek`


