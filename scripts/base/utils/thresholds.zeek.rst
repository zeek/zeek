:tocdepth: 3

base/utils/thresholds.zeek
==========================
.. bro:namespace:: GLOBAL

Functions for using multiple thresholds with a counting tracker.  For
example, you may want to generate a notice when something happens 10 times
and again when it happens 100 times but nothing in between.  You can use
the :bro:id:`check_threshold` function to define your threshold points
and the :bro:type:`TrackCount` variable where you are keeping track of your
counter.

:Namespace: GLOBAL

Summary
~~~~~~~
Redefinable Options
###################
========================================================================== ==========================================================
:bro:id:`default_notice_thresholds`: :bro:type:`vector` :bro:attr:`&redef` The thresholds you would like to use as defaults with the 
                                                                           :bro:id:`default_check_threshold` function.
========================================================================== ==========================================================

Types
#####
========================================== =
:bro:type:`TrackCount`: :bro:type:`record` 
========================================== =

Functions
#########
======================================================= ====================================================================
:bro:id:`check_threshold`: :bro:type:`function`         This will check if a :bro:type:`TrackCount` variable has crossed any
                                                        thresholds in a given set.
:bro:id:`default_check_threshold`: :bro:type:`function` This will use the :bro:id:`default_notice_thresholds` variable to
                                                        check a :bro:type:`TrackCount` variable to see if it has crossed
                                                        another threshold.
:bro:id:`new_track_count`: :bro:type:`function`         
======================================================= ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: default_notice_thresholds

   :Type: :bro:type:`vector` of :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      [30, 100, 1000, 10000, 100000, 1000000, 10000000]

   The thresholds you would like to use as defaults with the 
   :bro:id:`default_check_threshold` function.

Types
#####
.. bro:type:: TrackCount

   :Type: :bro:type:`record`

      n: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         The counter for the number of times something has happened.

      index: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         The index of the vector where the counter currently is.  This
         is used to track which threshold is currently being watched
         for.


Functions
#########
.. bro:id:: check_threshold

   :Type: :bro:type:`function` (v: :bro:type:`vector` of :bro:type:`count`, tracker: :bro:type:`TrackCount`) : :bro:type:`bool`

   This will check if a :bro:type:`TrackCount` variable has crossed any
   thresholds in a given set.
   

   :v: a vector holding counts that represent thresholds.
   

   :tracker: the record being used to track event counter and currently
            monitored threshold value.
   

   :returns: T if a threshold has been crossed, else F.

.. bro:id:: default_check_threshold

   :Type: :bro:type:`function` (tracker: :bro:type:`TrackCount`) : :bro:type:`bool`

   This will use the :bro:id:`default_notice_thresholds` variable to
   check a :bro:type:`TrackCount` variable to see if it has crossed
   another threshold.

.. bro:id:: new_track_count

   :Type: :bro:type:`function` () : :bro:type:`TrackCount`



