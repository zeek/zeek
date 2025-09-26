:orphan:

Package: base/protocols/dns
===========================

Support for Domain Name System (DNS) protocol analysis.

:doc:`/scripts/base/protocols/dns/__load__.zeek`


:doc:`/scripts/base/protocols/dns/consts.zeek`

   Types, errors, and fields for analyzing DNS data.  A helper file
   for DNS analysis scripts.

:doc:`/scripts/base/protocols/dns/main.zeek`

   Base DNS analysis script which tracks and logs DNS queries along with
   their responses.

:doc:`/scripts/base/protocols/dns/check-event-handlers.zeek`

   This script checks if DNS event handlers that will not be raised
   are used and raises a warning in those cases.

