:orphan:

Package: base/frameworks/packet-filter
======================================

The packet filter framework supports how Zeek sets its BPF capture filter.

:doc:`/scripts/base/frameworks/packet-filter/utils.zeek`


:doc:`/scripts/base/frameworks/packet-filter/__load__.zeek`


:doc:`/scripts/base/frameworks/packet-filter/main.zeek`

   This script supports how Zeek sets its BPF capture filter.  By default
   Zeek sets a capture filter that allows all traffic.  If a filter
   is set on the command line, that filter takes precedence over the default
   open filter and all filters defined in Zeek scripts with the
   :zeek:id:`capture_filters` and :zeek:id:`restrict_filters` variables.

:doc:`/scripts/base/frameworks/packet-filter/netstats.zeek`

   This script reports on packet loss from the various packet sources.
   When Zeek is reading input from trace files, this script will not
   report any packet loss statistics.

