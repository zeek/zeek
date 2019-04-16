:tocdepth: 3

base/protocols/conn/polling.zeek
================================
.. bro:namespace:: ConnPolling

Implements a generic way to poll connections looking for certain features
(e.g. monitor bytes transferred).  The specific feature of a connection
to look for, the polling interval, and the code to execute if the feature
is found are all controlled by user-defined callback functions.

:Namespace: ConnPolling

Summary
~~~~~~~
Functions
#########
================================================== =====================================
:bro:id:`ConnPolling::watch`: :bro:type:`function` Starts monitoring a given connection.
================================================== =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: ConnPolling::watch

   :Type: :bro:type:`function` (c: :bro:type:`connection`, callback: :bro:type:`function` (c: :bro:type:`connection`, cnt: :bro:type:`count`) : :bro:type:`interval`, cnt: :bro:type:`count`, i: :bro:type:`interval`) : :bro:type:`void`

   Starts monitoring a given connection.
   

   :c: The connection to watch.
   

   :callback: A callback function that takes as arguments the monitored
             *connection*, and counter *cnt* that increments each time
             the callback is called.  It returns an interval indicating
             how long in the future to schedule an event which will call
             the callback.  A negative return interval causes polling
             to stop.
   

   :cnt: The initial value of a counter which gets passed to *callback*.
   

   :i: The initial interval at which to schedule the next callback.
      May be ``0secs`` to poll right away.


