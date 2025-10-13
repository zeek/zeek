:orphan:

Package: base/frameworks/logging/postprocessors
===============================================

Support for postprocessors in the logging framework.

:doc:`/scripts/base/frameworks/logging/postprocessors/__load__.zeek`


:doc:`/scripts/base/frameworks/logging/postprocessors/scp.zeek`

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

:doc:`/scripts/base/frameworks/logging/postprocessors/sftp.zeek`

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

