:orphan:

Package: base/frameworks/tunnels
================================

The tunnels framework handles the tracking/logging of tunnels (e.g. Teredo,
AYIYA, or IP-in-IP such as 6to4 where "IP" is either IPv4 or IPv6).

:doc:`/scripts/base/frameworks/tunnels/__load__.bro`


:doc:`/scripts/base/frameworks/tunnels/main.bro`

   This script handles the tracking/logging of tunnels (e.g. Teredo,
   AYIYA, or IP-in-IP such as 6to4 where "IP" is either IPv4 or IPv6).
   
   For any connection that occurs over a tunnel, information about its
   encapsulating tunnels is also found in the *tunnel* field of
   :bro:type:`connection`.

