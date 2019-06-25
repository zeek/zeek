:tocdepth: 3

base/utils/thresholds.zeek
==========================
.. zeek:namespace:: GLOBAL

Functions for using multiple thresholds with a counting tracker.  For
example, you may want to generate a notice when something happens 10 times
and again when it happens 100 times but nothing in between.  You can use
the :zeek:id:`check_threshold` function to define your threshold points
and the :zeek:type:`TrackCount` variable where you are keeping track of your
counter.

:Namespace: GLOBAL

Summary
~~~~~~~
Redefinable Options
###################
============================================================================= ==========================================================
:zeek:id:`default_notice_thresholds`: :zeek:type:`vector` :zeek:attr:`&redef` The thresholds you would like to use as defaults with the 
                                                                              :zeek:id:`default_check_threshold` function.
============================================================================= ==========================================================

Types
#####
============================================ =
:zeek:type:`TrackCount`: :zeek:type:`record` 
============================================ =

Functions
#########
========================================================= =====================================================================
:zeek:id:`check_threshold`: :zeek:type:`function`         This will check if a :zeek:type:`TrackCount` variable has crossed any
                                                          thresholds in a given set.
:zeek:id:`default_check_threshold`: :zeek:type:`function` This will use the :zeek:id:`default_notice_thresholds` variable to
                                                          check a :zeek:type:`TrackCount` variable to see if it has crossed
                                                          another threshold.
:zeek:id:`new_track_count`: :zeek:type:`function`         
========================================================= =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: default_notice_thresholds

   :Type: :zeek:type:`vector` of :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         [30, 100, 1000, 10000, 100000, 1000000, 10000000]


   The thresholds you would like to use as defaults with the 
   :zeek:id:`default_check_threshold` function.

Types
#####
.. zeek:type:: TrackCount

   :Type: :zeek:type:`record`

      n: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         The counter for the number of times something has happened.

      index: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         The index of the vector where the counter currently is.  This
         is used to track which threshold is currently being watched
         for.


Functions
#########
.. zeek:id:: check_threshold

   :Type: :zeek:type:`function` (v: :zeek:type:`vector` of :zeek:type:`count`, tracker: :zeek:type:`TrackCount`) : :zeek:type:`bool`

   This will check if a :zeek:type:`TrackCount` variable has crossed any
   thresholds in a given set.
   

   :v: a vector holding counts that represent thresholds.
   

   :tracker: the record being used to track event counter and currently
            monitored threshold value.
   

   :returns: T if a threshold has been crossed, else F.

.. zeek:id:: default_check_threshold

   :Type: :zeek:type:`function` (tracker: :zeek:type:`TrackCount`) : :zeek:type:`bool`

   This will use the :zeek:id:`default_notice_thresholds` variable to
   check a :zeek:type:`TrackCount` variable to see if it has crossed
   another threshold.

.. zeek:id:: new_track_count

   :Type: :zeek:type:`function` () : :zeek:type:`TrackCount`



