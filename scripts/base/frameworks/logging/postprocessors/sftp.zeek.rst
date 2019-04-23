:tocdepth: 3

base/frameworks/logging/postprocessors/sftp.zeek
================================================
.. zeek:namespace:: Log

This script defines a postprocessing function that can be applied
to a logging filter in order to automatically SFTP
a log stream (or a subset of it) to a remote host at configurable
rotation time intervals.  Generally, to use this functionality
you must handle the :zeek:id:`zeek_init` event and do the following
in your handler:

1) Create a new :zeek:type:`Log::Filter` record that defines a name/path,
   rotation interval, and set the ``postprocessor`` to
   :zeek:id:`Log::sftp_postprocessor`.
2) Add the filter to a logging stream using :zeek:id:`Log::add_filter`.
3) Add a table entry to :zeek:id:`Log::sftp_destinations` for the filter's
   writer/path pair which defines a set of :zeek:type:`Log::SFTPDestination`
   records.

:Namespace: Log

Summary
~~~~~~~
Redefinable Options
###################
================================================================================== ================================================================
:zeek:id:`Log::sftp_rotation_date_format`: :zeek:type:`string` :zeek:attr:`&redef` Default naming format for timestamps embedded into log filenames
                                                                                   that use the SFTP rotator.
================================================================================== ================================================================

State Variables
###############
===================================================== =======================================================================
:zeek:id:`Log::sftp_destinations`: :zeek:type:`table` A table indexed by a particular log writer and filter path, that yields
                                                      a set of remote destinations.
===================================================== =======================================================================

Types
#####
====================================================== =======================================================================
:zeek:type:`Log::SFTPDestination`: :zeek:type:`record` A container that describes the remote destination for the SFTP command,
                                                       comprised of the username, host, and path at which to upload the file.
====================================================== =======================================================================

Functions
#########
========================================================= =============================================================
:zeek:id:`Log::sftp_postprocessor`: :zeek:type:`function` Securely transfers the rotated log to all the remote hosts
                                                          defined in :zeek:id:`Log::sftp_destinations` and then deletes
                                                          the local copy of the rotated log.
========================================================= =============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Log::sftp_rotation_date_format

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"%Y-%m-%d-%H-%M-%S"``

   Default naming format for timestamps embedded into log filenames
   that use the SFTP rotator.

State Variables
###############
.. zeek:id:: Log::sftp_destinations

   :Type: :zeek:type:`table` [:zeek:type:`Log::Writer`, :zeek:type:`string`] of :zeek:type:`set` [:zeek:type:`Log::SFTPDestination`]
   :Default: ``{}``

   A table indexed by a particular log writer and filter path, that yields
   a set of remote destinations.  The :zeek:id:`Log::sftp_postprocessor`
   function queries this table upon log rotation and performs a secure
   transfer of the rotated log to each destination in the set.  This
   table can be modified at run-time.

Types
#####
.. zeek:type:: Log::SFTPDestination

   :Type: :zeek:type:`record`

      user: :zeek:type:`string`
         The remote user to log in as.  A trust mechanism should be
         pre-established.

      host: :zeek:type:`string`
         The remote host to which to transfer logs.

      host_port: :zeek:type:`count` :zeek:attr:`&default` = ``22`` :zeek:attr:`&optional`
         The port to connect to. Defaults to 22

      path: :zeek:type:`string`
         The path/directory on the remote host to send logs.

   A container that describes the remote destination for the SFTP command,
   comprised of the username, host, and path at which to upload the file.

Functions
#########
.. zeek:id:: Log::sftp_postprocessor

   :Type: :zeek:type:`function` (info: :zeek:type:`Log::RotationInfo`) : :zeek:type:`bool`

   Securely transfers the rotated log to all the remote hosts
   defined in :zeek:id:`Log::sftp_destinations` and then deletes
   the local copy of the rotated log.  It's not active when
   reading from trace files.
   

   :info: A record holding meta-information about the log file to be
         postprocessed.
   

   :returns: True if sftp system command was initiated or
            if no destination was configured for the log as described
            by *info*.


