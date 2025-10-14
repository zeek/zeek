:tocdepth: 3

base/utils/time.zeek
====================



Summary
~~~~~~~
Functions
#########
======================================================= ========================================================================
:zeek:id:`duration_to_mins_secs`: :zeek:type:`function` Given an interval, returns a string representing the minutes and seconds
                                                        in the interval (for example, "3m34s").
======================================================= ========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: duration_to_mins_secs
   :source-code: base/utils/time.zeek 4 8

   :Type: :zeek:type:`function` (dur: :zeek:type:`interval`) : :zeek:type:`string`

   Given an interval, returns a string representing the minutes and seconds
   in the interval (for example, "3m34s").


