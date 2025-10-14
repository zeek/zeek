:orphan:

Package: base/protocols/dhcp
============================

Support for Dynamic Host Configuration Protocol (DHCP) analysis.

:doc:`/scripts/base/protocols/dhcp/__load__.zeek`


:doc:`/scripts/base/protocols/dhcp/consts.zeek`

   Types, errors, and fields for analyzing DHCP data.  A helper file
   for DHCP analysis scripts.

:doc:`/scripts/base/protocols/dhcp/main.zeek`

   Analyze DHCP traffic and provide a log that is organized around
   the idea of a DHCP "conversation" defined by messages exchanged within
   a relatively short period of time using the same transaction ID.
   The log will have information from clients and servers to give a more
   complete picture of what happened.

