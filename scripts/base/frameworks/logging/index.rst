:orphan:

Package: base/frameworks/logging
================================

The logging framework provides a flexible key-value based logging interface.

:doc:`/scripts/base/frameworks/logging/__load__.zeek`


:doc:`/scripts/base/frameworks/logging/main.zeek`

   The Zeek logging interface.
   
   See :doc:`/frameworks/logging` for an introduction to Zeek's
   logging framework.

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

:doc:`/scripts/base/frameworks/logging/writers/ascii.zeek`

   Interface for the ASCII log writer.  Redefinable options are available
   to tweak the output format of ASCII logs.
   
   The ASCII writer currently supports one writer-specific per-filter config
   option: setting ``tsv`` to the string ``T`` turns the output into
   "tab-separated-value" mode where only a single header row with the column
   names is printed out as meta information, with no "# fields" prepended; no
   other meta data gets included in that mode.  Example filter using this::
   
      local f: Log::Filter = [$name = "my-filter",
                              $writer = Log::WRITER_ASCII,
                              $config = table(["tsv"] = "T")];
   

:doc:`/scripts/base/frameworks/logging/writers/sqlite.zeek`

   Interface for the SQLite log writer. Redefinable options are available
   to tweak the output format of the SQLite reader.
   
   See :doc:`/frameworks/logging-input-sqlite` for an introduction on how to
   use the SQLite log writer.
   
   The SQL writer currently supports one writer-specific filter option via
   ``config``: setting ``tablename`` sets the name of the table that is used
   or created in the SQLite database. An example for this is given in the
   introduction mentioned above.

:doc:`/scripts/base/frameworks/logging/writers/none.zeek`

   Interface for the None log writer. This writer is mainly for debugging.

