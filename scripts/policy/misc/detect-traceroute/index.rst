:orphan:

Package: policy/misc/detect-traceroute
======================================

Detect hosts that are running traceroute.

:doc:`/scripts/policy/misc/detect-traceroute/__load__.bro`


:doc:`/scripts/policy/misc/detect-traceroute/main.bro`

   This script detects a large number of ICMP Time Exceeded messages heading
   toward hosts that have sent low TTL packets. It generates a notice when the
   number of ICMP Time Exceeded messages for a source-destination pair exceeds
   a threshold.

