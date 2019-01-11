:tocdepth: 3

base/utils/dir.bro
==================
.. bro:namespace:: Dir


:Namespace: Dir
:Imports: :doc:`base/frameworks/reporter </scripts/base/frameworks/reporter/index>`, :doc:`base/utils/exec.bro </scripts/base/utils/exec.bro>`, :doc:`base/utils/paths.bro </scripts/base/utils/paths.bro>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================== =====================================================================
:bro:id:`Dir::polling_interval`: :bro:type:`interval` :bro:attr:`&redef` The default interval this module checks for files in directories when
                                                                         using the :bro:see:`Dir::monitor` function.
======================================================================== =====================================================================

Functions
#########
============================================ ==============================================================
:bro:id:`Dir::monitor`: :bro:type:`function` Register a directory to monitor with a callback that is called
                                             every time a previously unseen file is seen.
============================================ ==============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Dir::polling_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``30.0 secs``

   The default interval this module checks for files in directories when
   using the :bro:see:`Dir::monitor` function.

Functions
#########
.. bro:id:: Dir::monitor

   :Type: :bro:type:`function` (dir: :bro:type:`string`, callback: :bro:type:`function` (fname: :bro:type:`string`) : :bro:type:`void`, poll_interval: :bro:type:`interval` :bro:attr:`&default` = :bro:see:`Dir::polling_interval` :bro:attr:`&optional`) : :bro:type:`void`

   Register a directory to monitor with a callback that is called
   every time a previously unseen file is seen.  If a file is deleted
   and seen to be gone, then the file is available for being seen again
   in the future.
   

   :dir: The directory to monitor for files.
   

   :callback: Callback that gets executed with each file name
             that is found.  Filenames are provided with the full path.
   

   :poll_interval: An interval at which to check for new files.


