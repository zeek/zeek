:tocdepth: 3

base/utils/dir.zeek
===================
.. zeek:namespace:: Dir


:Namespace: Dir
:Imports: :doc:`base/frameworks/reporter </scripts/base/frameworks/reporter/index>`, :doc:`base/utils/exec.zeek </scripts/base/utils/exec.zeek>`, :doc:`base/utils/paths.zeek </scripts/base/utils/paths.zeek>`

Summary
~~~~~~~
Runtime Options
###############
=========================================================================== =====================================================================
:zeek:id:`Dir::polling_interval`: :zeek:type:`interval` :zeek:attr:`&redef` The default interval this module checks for files in directories when
                                                                            using the :zeek:see:`Dir::monitor` function.
=========================================================================== =====================================================================

Functions
#########
============================================== ==============================================================
:zeek:id:`Dir::monitor`: :zeek:type:`function` Register a directory to monitor with a callback that is called
                                               every time a previously unseen file is seen.
============================================== ==============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Dir::polling_interval

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``30.0 secs``

   The default interval this module checks for files in directories when
   using the :zeek:see:`Dir::monitor` function.

Functions
#########
.. zeek:id:: Dir::monitor

   :Type: :zeek:type:`function` (dir: :zeek:type:`string`, callback: :zeek:type:`function` (fname: :zeek:type:`string`) : :zeek:type:`void`, poll_interval: :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Dir::polling_interval` :zeek:attr:`&optional`) : :zeek:type:`void`

   Register a directory to monitor with a callback that is called
   every time a previously unseen file is seen.  If a file is deleted
   and seen to be gone, then the file is available for being seen again
   in the future.
   

   :dir: The directory to monitor for files.
   

   :callback: Callback that gets executed with each file name
             that is found.  Filenames are provided with the full path.
   

   :poll_interval: An interval at which to check for new files.


