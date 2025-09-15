:orphan:

Package: base/protocols/imap
============================

Support for the Internet Message Access Protocol (IMAP).

Note that currently the IMAP analyzer only supports analyzing IMAP sessions
until they do or do not switch to TLS using StartTLS. Hence, we do not get
mails from IMAP sessions, only X509 certificates.

:doc:`/scripts/base/protocols/imap/__load__.zeek`


:doc:`/scripts/base/protocols/imap/main.zeek`


