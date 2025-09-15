:orphan:

Package: base/frameworks/supervisor
===================================


:doc:`/scripts/base/frameworks/supervisor/api.zeek`

   The Zeek process supervision API.
   This API was introduced in Zeek 3.1.0 and considered unstable until 4.0.0.
   That is, it may change in various incompatible ways without warning or
   deprecation until the stable 4.0.0 release.

:doc:`/scripts/base/frameworks/supervisor/__load__.zeek`


:doc:`/scripts/base/frameworks/supervisor/control.zeek`

   The Zeek process supervision (remote) control API.  This defines a Broker topic
   prefix and events that can be used to control an external Zeek supervisor process.
   This API was introduced in Zeek 3.1.0 and considered unstable until 4.0.0.
   That is, it may change in various incompatible ways without warning or
   deprecation until the stable 4.0.0 release.

:doc:`/scripts/base/frameworks/supervisor/main.zeek`

   Implements Zeek process supervision API and default behavior for its
   associated (remote) control events.

