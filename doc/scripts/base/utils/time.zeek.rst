:tocdepth: 3

base/utils/time.zeek
====================

Time-related functions.


Summary
~~~~~~~
Constants
#########
===================================== ========================================
:zeek:id:`null_ts`: :zeek:type:`time` Time value representing the 0 timestamp.
===================================== ========================================

Functions
#########
======================================================= ========================================================================
:zeek:id:`duration_to_mins_secs`: :zeek:type:`function` Given an interval, returns a string representing the minutes and seconds
                                                        in the interval (for example, "3m34s").
:zeek:id:`get_packet_lag`: :zeek:type:`function`        Calculate the packet lag, i.e.
======================================================= ========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: null_ts
   :source-code: base/utils/time.zeek 12 12

   :Type: :zeek:type:`time`
   :Default: ``0.0``

   Time value representing the 0 timestamp.

Functions
#########
.. zeek:id:: duration_to_mins_secs
   :source-code: base/utils/time.zeek 5 9

   :Type: :zeek:type:`function` (dur: :zeek:type:`interval`) : :zeek:type:`string`

   Given an interval, returns a string representing the minutes and seconds
   in the interval (for example, "3m34s").

.. zeek:id:: get_packet_lag
   :source-code: base/utils/time.zeek 17 28

   :Type: :zeek:type:`function` () : :zeek:type:`interval`

   Calculate the packet lag, i.e. the difference between wall clock and the
   timestamp of the currently processed packet. If Zeek is not processing a
   packet, the function returns a 0 interval value.


