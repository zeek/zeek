:orphan:

Package: base/frameworks/supervisor
===================================


:doc:`/scripts/base/frameworks/supervisor/api.zeek`

   The Zeek process supervision API.

:doc:`/scripts/base/frameworks/supervisor/__load__.zeek`


:doc:`/scripts/base/frameworks/supervisor/control.zeek`

   The Zeek process supervision (remote) control API.  This defines a Broker topic
   prefix and events that can be used to control an external Zeek supervisor process.

:doc:`/scripts/base/frameworks/supervisor/main.zeek`

   Implements Zeek process supervision API and default behavior for its
   associated (remote) control events.

