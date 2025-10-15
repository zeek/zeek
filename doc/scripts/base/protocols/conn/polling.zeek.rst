:tocdepth: 3

base/protocols/conn/polling.zeek
================================
.. zeek:namespace:: ConnPolling

Implements a generic way to poll connections looking for certain features
(e.g. monitor bytes transferred).  The specific feature of a connection
to look for, the polling interval, and the code to execute if the feature
is found are all controlled by user-defined callback functions.

:Namespace: ConnPolling

Summary
~~~~~~~
Functions
#########
==================================================== =====================================
:zeek:id:`ConnPolling::watch`: :zeek:type:`function` Starts monitoring a given connection.
==================================================== =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: ConnPolling::watch
   :source-code: base/protocols/conn/polling.zeek 47 51

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, callback: :zeek:type:`function` (c: :zeek:type:`connection`, cnt: :zeek:type:`count`) : :zeek:type:`interval`, cnt: :zeek:type:`count`, i: :zeek:type:`interval`) : :zeek:type:`void`

   Starts monitoring a given connection.
   

   :param c: The connection to watch.
   

   :param callback: A callback function that takes as arguments the monitored
             *connection*, and counter *cnt* that increments each time
             the callback is called.  It returns an interval indicating
             how long in the future to schedule an event which will call
             the callback.  A negative return interval causes polling
             to stop.
   

   :param cnt: The initial value of a counter which gets passed to *callback*.
   

   :param i: The initial interval at which to schedule the next callback.
      May be ``0secs`` to poll right away.


