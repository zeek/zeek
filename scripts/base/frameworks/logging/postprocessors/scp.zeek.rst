:tocdepth: 3

base/frameworks/logging/postprocessors/scp.zeek
===============================================
.. zeek:namespace:: Log

This script defines a postprocessing function that can be applied
to a logging filter in order to automatically SCP (secure copy)
a log stream (or a subset of it) to a remote host at configurable
rotation time intervals.  Generally, to use this functionality
you must handle the :zeek:id:`zeek_init` event and do the following
in your handler:

1) Create a new :zeek:type:`Log::Filter` record that defines a name/path,
   rotation interval, and set the ``postprocessor`` to
   :zeek:id:`Log::scp_postprocessor`.
2) Add the filter to a logging stream using :zeek:id:`Log::add_filter`.
3) Add a table entry to :zeek:id:`Log::scp_destinations` for the filter's
   writer/path pair which defines a set of :zeek:type:`Log::SCPDestination`
   records.

:Namespace: Log

Summary
~~~~~~~
Redefinable Options
###################
================================================================================= ================================================================
:zeek:id:`Log::scp_rotation_date_format`: :zeek:type:`string` :zeek:attr:`&redef` Default naming format for timestamps embedded into log filenames
                                                                                  that use the SCP rotator.
================================================================================= ================================================================

State Variables
###############
==================================================== =======================================================================
:zeek:id:`Log::scp_destinations`: :zeek:type:`table` A table indexed by a particular log writer and filter path, that yields
                                                     a set of remote destinations.
==================================================== =======================================================================

Types
#####
===================================================== =====================================================================
:zeek:type:`Log::SCPDestination`: :zeek:type:`record` A container that describes the remote destination for the SCP command
                                                      argument as ``user@host:path``.
===================================================== =====================================================================

Functions
#########
======================================================== ============================================================
:zeek:id:`Log::scp_postprocessor`: :zeek:type:`function` Secure-copies the rotated log to all the remote hosts
                                                         defined in :zeek:id:`Log::scp_destinations` and then deletes
                                                         the local copy of the rotated log.
======================================================== ============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Log::scp_rotation_date_format

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"%Y-%m-%d-%H-%M-%S"``

   Default naming format for timestamps embedded into log filenames
   that use the SCP rotator.

State Variables
###############
.. zeek:id:: Log::scp_destinations

   :Type: :zeek:type:`table` [:zeek:type:`Log::Writer`, :zeek:type:`string`] of :zeek:type:`set` [:zeek:type:`Log::SCPDestination`]
   :Default: ``{}``

   A table indexed by a particular log writer and filter path, that yields
   a set of remote destinations.  The :zeek:id:`Log::scp_postprocessor`
   function queries this table upon log rotation and performs a secure
   copy of the rotated log to each destination in the set.  This
   table can be modified at run-time.

Types
#####
.. zeek:type:: Log::SCPDestination

   :Type: :zeek:type:`record`

      user: :zeek:type:`string`
         The remote user to log in as.  A trust mechanism should be
         pre-established.

      host: :zeek:type:`string`
         The remote host to which to transfer logs.

      path: :zeek:type:`string`
         The path/directory on the remote host to send logs.

   A container that describes the remote destination for the SCP command
   argument as ``user@host:path``.

Functions
#########
.. zeek:id:: Log::scp_postprocessor

   :Type: :zeek:type:`function` (info: :zeek:type:`Log::RotationInfo`) : :zeek:type:`bool`

   Secure-copies the rotated log to all the remote hosts
   defined in :zeek:id:`Log::scp_destinations` and then deletes
   the local copy of the rotated log.  It's not active when
   reading from trace files.
   

   :info: A record holding meta-information about the log file to be
         postprocessed.
   

   :returns: True if secure-copy system command was initiated or
            if no destination was configured for the log as described
            by *info*.


