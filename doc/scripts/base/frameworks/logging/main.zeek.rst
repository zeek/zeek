:tocdepth: 3

base/frameworks/logging/main.zeek
=================================
.. zeek:namespace:: Log

The Zeek logging interface.

See :doc:`/frameworks/logging` for an introduction to Zeek's
logging framework.

:Namespace: Log
:Imports: :doc:`base/bif/logging.bif.zeek </scripts/base/bif/logging.bif.zeek>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================================== ==================================================================
:zeek:id:`Log::default_rotation_dir`: :zeek:type:`string` :zeek:attr:`&redef`                  Default rotation directory to use for the *dir* field of
                                                                                               :zeek:see:`Log::RotationPath` during calls to
                                                                                               :zeek:see:`Log::rotation_format_func`.
:zeek:id:`Log::default_rotation_postprocessor_cmd_env`: :zeek:type:`table` :zeek:attr:`&redef` This table contains environment variables to be used for the
                                                                                               :zeek:see:`Log::default_rotation_postprocessor_cmd` command
                                                                                               when executed via :zeek:see:`Log::run_rotation_postprocessor_cmd`.
============================================================================================== ==================================================================

Redefinable Options
###################
=========================================================================================== =====================================================================
:zeek:id:`Log::default_ext_prefix`: :zeek:type:`string` :zeek:attr:`&redef`                 A prefix for extension fields which can be optionally prefixed
                                                                                            on all log lines by setting the `ext_func` field in the
                                                                                            log filter.
:zeek:id:`Log::default_field_name_map`: :zeek:type:`table` :zeek:attr:`&redef`              Default field name mapping for renaming fields in a logging framework
                                                                                            filter.
:zeek:id:`Log::default_logdir`: :zeek:type:`string` :zeek:attr:`&redef`                     Default logging directory.
:zeek:id:`Log::default_mail_alarms_interval`: :zeek:type:`interval` :zeek:attr:`&redef`     Default alarm summary mail interval.
:zeek:id:`Log::default_max_delay_interval`: :zeek:type:`interval` :zeek:attr:`&redef`       Maximum default log write delay for a stream.
:zeek:id:`Log::default_max_delay_queue_size`: :zeek:type:`count` :zeek:attr:`&redef`        The maximum length of the write delay queue per stream.
:zeek:id:`Log::default_rotation_date_format`: :zeek:type:`string` :zeek:attr:`&redef`       Default naming format for timestamps embedded into filenames.
:zeek:id:`Log::default_rotation_interval`: :zeek:type:`interval` :zeek:attr:`&redef`        Default rotation interval to use for filters that do not specify
                                                                                            an interval.
:zeek:id:`Log::default_rotation_postprocessor_cmd`: :zeek:type:`string` :zeek:attr:`&redef` Default shell command to run on rotated files.
:zeek:id:`Log::default_rotation_postprocessors`: :zeek:type:`table` :zeek:attr:`&redef`     Specifies the default postprocessor function per writer type.
:zeek:id:`Log::default_scope_sep`: :zeek:type:`string` :zeek:attr:`&redef`                  Default separator for log field scopes when logs are unrolled and
                                                                                            flattened.
:zeek:id:`Log::default_writer`: :zeek:type:`Log::Writer` :zeek:attr:`&redef`                Default writer to use if a filter does not specify anything else.
:zeek:id:`Log::empty_field`: :zeek:type:`string` :zeek:attr:`&redef`                        Default string to use for empty fields.
:zeek:id:`Log::enable_local_logging`: :zeek:type:`bool` :zeek:attr:`&redef`                 If true, local logging is by default enabled for all filters.
:zeek:id:`Log::enable_remote_logging`: :zeek:type:`bool` :zeek:attr:`&redef`                If true, remote logging is by default enabled for all filters.
:zeek:id:`Log::print_log_path`: :zeek:type:`string` :zeek:attr:`&redef`                     If :zeek:see:`Log::print_to_log` is enabled to write to a print log,
                                                                                            this is the path to which the print Log Stream writes to
:zeek:id:`Log::print_to_log`: :zeek:type:`Log::PrintLogType` :zeek:attr:`&redef`            Set configuration for ``print`` statements redirected to logs.
:zeek:id:`Log::separator`: :zeek:type:`string` :zeek:attr:`&redef`                          Default separator to use between fields.
:zeek:id:`Log::set_separator`: :zeek:type:`string` :zeek:attr:`&redef`                      Default separator to use between elements of a set.
:zeek:id:`Log::unset_field`: :zeek:type:`string` :zeek:attr:`&redef`                        Default string to use for an unset &optional field.
=========================================================================================== =====================================================================

Constants
#########
=================================================== =========================================================================
:zeek:id:`Log::no_filter`: :zeek:type:`Log::Filter` Sentinel value for indicating that a filter was not found when looked up.
=================================================== =========================================================================

State Variables
###############
================================================== ========================================================
:zeek:id:`Log::active_streams`: :zeek:type:`table` The streams which are currently active and not disabled.
================================================== ========================================================

Types
#####
================================================================== ==============================================================================
:zeek:type:`Log::DelayToken`: :zeek:type:`opaque`                  Type of the opaque value returned by :zeek:see:`Log::delay`.
:zeek:type:`Log::Filter`: :zeek:type:`record`                      A filter type describes how to customize logging streams.
:zeek:type:`Log::ID`: :zeek:type:`enum`                            Type that defines an ID unique to each log stream.
:zeek:type:`Log::PolicyHook`: :zeek:type:`hook`                    A hook type to implement filtering policy at log filter
                                                                   granularity.
:zeek:type:`Log::PostDelayCallback`: :zeek:type:`function`         Type of function to invoke when delaying a log write has completed.
:zeek:type:`Log::PrintLogInfo`: :zeek:type:`record`                If :zeek:see:`Log::print_to_log` is set to redirect, ``print`` statements will
                                                                   automatically populate log entries with the fields contained in this record.
:zeek:type:`Log::PrintLogType`: :zeek:type:`enum`                  Configurations for :zeek:see:`Log::print_to_log`
:zeek:type:`Log::RotationFmtInfo`: :zeek:type:`record`             Information passed into rotation format callback function given by
                                                                   :zeek:see:`Log::rotation_format_func`.
:zeek:type:`Log::RotationInfo`: :zeek:type:`record`                Information passed into rotation callback functions.
:zeek:type:`Log::RotationPath`: :zeek:type:`record`                A log file rotation path specification that's returned by the
                                                                   user-customizable :zeek:see:`Log::rotation_format_func`.
:zeek:type:`Log::RotationPostProcessorFunc`: :zeek:type:`function` The function type for log rotation post processors.
:zeek:type:`Log::Stream`: :zeek:type:`record`                      Type defining the content of a logging stream.
:zeek:type:`Log::StreamPolicyHook`: :zeek:type:`hook`              A hook type to implement filtering policy.
:zeek:type:`Log::Writer`: :zeek:type:`enum`                        
================================================================== ==============================================================================

Redefinitions
#############
======================================================================================= =============================================================
:zeek:type:`Log::Filter`: :zeek:type:`record`                                           
                                                                                        
                                                                                        :New Fields: :zeek:type:`Log::Filter`
                                                                                        
                                                                                          policy: :zeek:type:`Log::PolicyHook` :zeek:attr:`&optional`
                                                                                            Policy hooks can adjust log entry values and veto
                                                                                            the writing of a log entry for the record passed
                                                                                            into it.
:zeek:id:`Log::default_rotation_postprocessors`: :zeek:type:`table` :zeek:attr:`&redef` 
======================================================================================= =============================================================

Events
######
============================================= =========================================
:zeek:id:`Log::log_print`: :zeek:type:`event` Event for accessing logged print records.
============================================= =========================================

Hooks
#####
===================================================================== ===========================
:zeek:id:`Log::log_stream_policy`: :zeek:type:`Log::StreamPolicyHook` The global log policy hook.
===================================================================== ===========================

Functions
#########
=============================================================================== ==========================================================================
:zeek:id:`Log::add_default_filter`: :zeek:type:`function`                       Adds a default :zeek:type:`Log::Filter` record with ``name`` field
                                                                                set as "default" to a given logging stream.
:zeek:id:`Log::add_filter`: :zeek:type:`function`                               Adds a custom filter to an existing logging stream.
:zeek:id:`Log::create_stream`: :zeek:type:`function`                            Creates a new logging stream with the default filter.
:zeek:id:`Log::default_ext_func`: :zeek:type:`function` :zeek:attr:`&redef`     Default log extension function in the case that you would like to
                                                                                apply the same extensions to all logs.
:zeek:id:`Log::default_path_func`: :zeek:type:`function` :zeek:attr:`&redef`    Builds the default path values for log filters if not otherwise
                                                                                specified by a filter.
:zeek:id:`Log::delay`: :zeek:type:`function`                                    Delay a log write.
:zeek:id:`Log::delay_finish`: :zeek:type:`function`                             Release a delay reference taken with :zeek:see:`Log::delay`.
:zeek:id:`Log::disable_stream`: :zeek:type:`function`                           Disables a currently enabled logging stream.
:zeek:id:`Log::empty_post_delay_cb`: :zeek:type:`function`                      Represents a post delay callback that simply returns T.
:zeek:id:`Log::enable_stream`: :zeek:type:`function`                            Enables a previously disabled logging stream.
:zeek:id:`Log::flush`: :zeek:type:`function`                                    Flushes any currently buffered output for all the writers of a given
                                                                                logging stream.
:zeek:id:`Log::get_delay_queue_size`: :zeek:type:`function`                     Get the current size of the delay queue for a stream.
:zeek:id:`Log::get_filter`: :zeek:type:`function`                               Gets a filter associated with an existing logging stream.
:zeek:id:`Log::get_filter_names`: :zeek:type:`function`                         Gets the names of all filters associated with an existing
                                                                                logging stream.
:zeek:id:`Log::remove_default_filter`: :zeek:type:`function`                    Removes the :zeek:type:`Log::Filter` with ``name`` field equal to
                                                                                "default".
:zeek:id:`Log::remove_filter`: :zeek:type:`function`                            Removes a filter from an existing logging stream.
:zeek:id:`Log::remove_stream`: :zeek:type:`function`                            Removes a logging stream completely, stopping all the threads.
:zeek:id:`Log::rotation_format_func`: :zeek:type:`function` :zeek:attr:`&redef` A function that one may use to customize log file rotation paths.
:zeek:id:`Log::run_rotation_postprocessor_cmd`: :zeek:type:`function`           Runs a command given by :zeek:id:`Log::default_rotation_postprocessor_cmd`
                                                                                on a rotated file.
:zeek:id:`Log::set_buf`: :zeek:type:`function`                                  Sets the buffering status for all the writers of a given logging stream.
:zeek:id:`Log::set_max_delay_interval`: :zeek:type:`function`                   Set the maximum delay for a stream.
:zeek:id:`Log::set_max_delay_queue_size`: :zeek:type:`function`                 Set the given stream's delay queue size.
:zeek:id:`Log::write`: :zeek:type:`function`                                    Writes a new log line/entry to a logging stream.
=============================================================================== ==========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Log::default_rotation_dir
   :source-code: base/frameworks/logging/main.zeek 141 141

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``
   :Redefinition: from :doc:`/scripts/policy/frameworks/management/persistence.zeek`

      ``=``::

         build_path(Management::get_spool_dir(), log-queue)


   Default rotation directory to use for the *dir* field of
   :zeek:see:`Log::RotationPath` during calls to
   :zeek:see:`Log::rotation_format_func`.  An empty string implies
   using the current working directory;

.. zeek:id:: Log::default_rotation_postprocessor_cmd_env
   :source-code: base/frameworks/logging/main.zeek 181 181

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   This table contains environment variables to be used for the
   :zeek:see:`Log::default_rotation_postprocessor_cmd` command
   when executed via :zeek:see:`Log::run_rotation_postprocessor_cmd`.
   
   The entries in this table will be prepended with ``ZEEK_ARG_``
   as done by :zeek:see:`system_env`.

Redefinable Options
###################
.. zeek:id:: Log::default_ext_prefix
   :source-code: base/frameworks/logging/main.zeek 208 208

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"_"``

   A prefix for extension fields which can be optionally prefixed
   on all log lines by setting the `ext_func` field in the
   log filter.

.. zeek:id:: Log::default_field_name_map
   :source-code: base/frameworks/logging/main.zeek 197 197

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Default field name mapping for renaming fields in a logging framework
   filter.  This is typically used to ease integration with external
   data storage and analysis systems.

.. zeek:id:: Log::default_logdir
   :source-code: base/frameworks/logging/main.zeek 35 35

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Default logging directory. An empty string implies using the
   current working directory.
   
   This directory is also used for rotated logs in cases where
   :zeek:see:`Log::rotation_format_func` returns a record with
   an empty or unset ``dir`` field.

.. zeek:id:: Log::default_mail_alarms_interval
   :source-code: base/frameworks/logging/main.zeek 192 192

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0 secs``

   Default alarm summary mail interval. Zero disables alarm summary
   mails.
   
   Note that this is overridden by the ZeekControl MailAlarmsInterval
   option.

.. zeek:id:: Log::default_max_delay_interval
   :source-code: base/frameworks/logging/main.zeek 221 221

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``200.0 msecs``

   Maximum default log write delay for a stream. A :zeek:see:`Log::write`
   operation is delayed by at most this interval if :zeek:see:`Log::delay`
   is called within :zeek:see:`Log::log_stream_policy`.

.. zeek:id:: Log::default_max_delay_queue_size
   :source-code: base/frameworks/logging/main.zeek 227 227

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1000``

   The maximum length of the write delay queue per stream. If exceeded,
   an attempt is made to evict the oldest writes from the queue. If
   post delay callbacks re-delay a write operation, the maximum queue
   size may be exceeded.

.. zeek:id:: Log::default_rotation_date_format
   :source-code: base/frameworks/logging/main.zeek 170 170

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"%Y-%m-%d-%H-%M-%S"``

   Default naming format for timestamps embedded into filenames.
   Uses a ``strftime()`` style.

.. zeek:id:: Log::default_rotation_interval
   :source-code: base/frameworks/logging/main.zeek 135 135

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0 secs``

   Default rotation interval to use for filters that do not specify
   an interval. Zero disables rotation.
   
   Note that this is overridden by the ZeekControl LogRotationInterval
   option.

.. zeek:id:: Log::default_rotation_postprocessor_cmd
   :source-code: base/frameworks/logging/main.zeek 173 173

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Default shell command to run on rotated files. Empty for none.

.. zeek:id:: Log::default_rotation_postprocessors
   :source-code: base/frameworks/logging/main.zeek 185 185

   :Type: :zeek:type:`table` [:zeek:type:`Log::Writer`] of :zeek:type:`function` (info: :zeek:type:`Log::RotationInfo`) : :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/frameworks/logging/main.zeek`

      ``+=``::

         Log::WRITER_ASCII = Log::default_ascii_rotation_postprocessor_func

   :Redefinition: from :doc:`/scripts/base/frameworks/logging/writers/none.zeek`

      ``+=``::

         Log::WRITER_NONE = LogNone::default_rotation_postprocessor_func


   Specifies the default postprocessor function per writer type.
   Entries in this table are initialized by each writer type.

.. zeek:id:: Log::default_scope_sep
   :source-code: base/frameworks/logging/main.zeek 203 203

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"."``

   Default separator for log field scopes when logs are unrolled and
   flattened.  This will be the string between field name components.
   For example, setting this to "_" will cause the typical field
   "id.orig_h" to turn into "id_orig_h".

.. zeek:id:: Log::default_writer
   :source-code: base/frameworks/logging/main.zeek 27 27

   :Type: :zeek:type:`Log::Writer`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``Log::WRITER_ASCII``

   Default writer to use if a filter does not specify anything else.

.. zeek:id:: Log::empty_field
   :source-code: base/frameworks/logging/main.zeek 48 48

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"(empty)"``

   Default string to use for empty fields. This should be different
   from *unset_field* to make the output unambiguous.
   Individual writers can use a different value.

.. zeek:id:: Log::enable_local_logging
   :source-code: base/frameworks/logging/main.zeek 21 21

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   If true, local logging is by default enabled for all filters.

.. zeek:id:: Log::enable_remote_logging
   :source-code: base/frameworks/logging/main.zeek 24 24

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   If true, remote logging is by default enabled for all filters.

.. zeek:id:: Log::print_log_path
   :source-code: base/frameworks/logging/main.zeek 101 101

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"print"``

   If :zeek:see:`Log::print_to_log` is enabled to write to a print log,
   this is the path to which the print Log Stream writes to

.. zeek:id:: Log::print_to_log
   :source-code: base/frameworks/logging/main.zeek 97 97

   :Type: :zeek:type:`Log::PrintLogType`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``Log::REDIRECT_NONE``

   Set configuration for ``print`` statements redirected to logs.

.. zeek:id:: Log::separator
   :source-code: base/frameworks/logging/main.zeek 39 39

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"\x09"``

   Default separator to use between fields.
   Individual writers can use a different value.

.. zeek:id:: Log::set_separator
   :source-code: base/frameworks/logging/main.zeek 43 43

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``","``

   Default separator to use between elements of a set.
   Individual writers can use a different value.

.. zeek:id:: Log::unset_field
   :source-code: base/frameworks/logging/main.zeek 52 52

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"-"``

   Default string to use for an unset &optional field.
   Individual writers can use a different value.

Constants
#########
.. zeek:id:: Log::no_filter
   :source-code: base/frameworks/logging/main.zeek 428 428

   :Type: :zeek:type:`Log::Filter`
   :Default:

      ::

         {
            name="<not found>"
            writer=Log::WRITER_ASCII
            path=<uninitialized>
            path_func=<uninitialized>
            include=<uninitialized>
            exclude=<uninitialized>
            log_local=T
            log_remote=T
            field_name_map={

            }
            scope_sep="."
            ext_prefix="_"
            ext_func=lambda_<2528247166937952945>
            ;
            interv=0 secs
            postprocessor=<uninitialized>
            config={

            }
            policy=<uninitialized>
         }


   Sentinel value for indicating that a filter was not found when looked up.

State Variables
###############
.. zeek:id:: Log::active_streams
   :source-code: base/frameworks/logging/main.zeek 626 626

   :Type: :zeek:type:`table` [:zeek:type:`Log::ID`] of :zeek:type:`Log::Stream`
   :Default: ``{}``

   The streams which are currently active and not disabled.
   This table is not meant to be modified by users!  Only use it for
   examining which streams are active.

Types
#####
.. zeek:type:: Log::DelayToken
   :source-code: base/frameworks/logging/main.zeek 647 647

   :Type: :zeek:type:`opaque` of LogDelayToken

   Type of the opaque value returned by :zeek:see:`Log::delay`. These
   values can be passed to :zeek:see:`Log::delay_finish` to release a
   delayed write operation.

.. zeek:type:: Log::Filter
   :source-code: base/frameworks/logging/main.zeek 230 323

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`
         Descriptive name to reference this filter.

      writer: :zeek:type:`Log::Writer` :zeek:attr:`&default` = :zeek:see:`Log::default_writer` :zeek:attr:`&optional`
         The logging writer implementation to use.

      path: :zeek:type:`string` :zeek:attr:`&optional`
         Output path for recording entries matching this
         filter.
         
         The specific interpretation of the string is up to the
         logging writer, and may for example be the destination
         file name. Generally, filenames are expected to be given
         without any extensions; writers will add appropriate
         extensions automatically.
         
         If this path is found to conflict with another filter's
         for the same writer type, it is automatically corrected
         by appending "-N", where N is the smallest integer greater
         or equal to 2 that allows the corrected path name to not
         conflict with another filter's.

      path_func: :zeek:type:`function` (id: :zeek:type:`Log::ID`, path: :zeek:type:`string`, rec: :zeek:type:`any`) : :zeek:type:`string` :zeek:attr:`&optional`
         A function returning the output path for recording entries
         matching this filter. This is similar to *path* yet allows
         to compute the string dynamically. It is ok to return
         different strings for separate calls, but be careful: it's
         easy to flood the disk by returning a new string for each
         connection.  Upon adding a filter to a stream, if neither
         ``path`` nor ``path_func`` is explicitly set by them, then
         :zeek:see:`Log::default_path_func` is used.
         

         :param id: The ID associated with the log stream.
         

         :param path: A suggested path value, which may be either the filter's
               ``path`` if defined, else a previous result from the
               function.  If no ``path`` is defined for the filter,
               then the first call to the function will contain an
               empty string.
         

         :param rec: An instance of the stream's ``columns`` type with its
              fields set to the values to be logged.
         

         :returns: The path to be used for the filter, which will be
                  subject to the same automatic correction rules as
                  the *path* field of :zeek:type:`Log::Filter` in the
                  case of conflicts with other filters trying to use
                  the same writer/path pair.

      include: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&optional`
         Subset of column names to record. If not given, all
         columns are recorded.

      exclude: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&optional`
         Subset of column names to exclude from recording. If not
         given, all columns are recorded.

      log_local: :zeek:type:`bool` :zeek:attr:`&default` = :zeek:see:`Log::enable_local_logging` :zeek:attr:`&optional`
         If true, entries are recorded locally.

      log_remote: :zeek:type:`bool` :zeek:attr:`&default` = :zeek:see:`Log::enable_remote_logging` :zeek:attr:`&optional`
         If true, entries are passed on to remote peers.

      field_name_map: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string` :zeek:attr:`&default` = :zeek:see:`Log::default_field_name_map` :zeek:attr:`&optional`
         Field name map to rename fields before the fields are written
         to the output.

      scope_sep: :zeek:type:`string` :zeek:attr:`&default` = :zeek:see:`Log::default_scope_sep` :zeek:attr:`&optional`
         A string that is used for unrolling and flattening field names
         for nested record types.

      ext_prefix: :zeek:type:`string` :zeek:attr:`&default` = :zeek:see:`Log::default_ext_prefix` :zeek:attr:`&optional`
         Default prefix for all extension fields. It's typically
         prudent to set this to something that Zeek's logging
         framework can't normally write out in a field name.

      ext_func: :zeek:type:`function` (path: :zeek:type:`string`) : :zeek:type:`any` :zeek:attr:`&default` = :zeek:see:`Log::default_ext_func` :zeek:attr:`&optional`
         Function to collect a log extension value.  If not specified,
         no log extension will be provided for the log.
         The return value from the function *must* be a record.

      interv: :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Log::default_rotation_interval` :zeek:attr:`&optional`
         Rotation interval. Zero disables rotation.

      postprocessor: :zeek:type:`function` (info: :zeek:type:`Log::RotationInfo`) : :zeek:type:`bool` :zeek:attr:`&optional`
         Callback function to trigger for rotated files. If not set, the
         default comes out of :zeek:id:`Log::default_rotation_postprocessors`.

      config: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string` :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         A key/value table that will be passed on to the writer.
         Interpretation of the values is left to the writer, but
         usually they will be used for configuration purposes.

      policy: :zeek:type:`Log::PolicyHook` :zeek:attr:`&optional`
         Policy hooks can adjust log entry values and veto
         the writing of a log entry for the record passed
         into it. Any hook that breaks from its body signals
         that Zeek won't log the entry passed into it.
         
         When no policy hook is defined, the filter inherits
         the hook from the stream it's associated with.

   A filter type describes how to customize logging streams.

.. zeek:type:: Log::ID
   :source-code: base/frameworks/logging/main.zeek 13 19

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Log::UNKNOWN Log::ID

         Dummy place-holder.

      .. zeek:enum:: Log::PRINTLOG Log::ID

         Print statements that have been redirected to a log stream.

      .. zeek:enum:: Broker::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/broker/log.zeek` is loaded)


      .. zeek:enum:: Cluster::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/cluster/main.zeek` is loaded)


      .. zeek:enum:: Config::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/config/main.zeek` is loaded)


      .. zeek:enum:: DPD::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/analyzer/dpd.zeek` is loaded)


      .. zeek:enum:: Analyzer::Logging::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/analyzer/logging.zeek` is loaded)


      .. zeek:enum:: Files::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/files/main.zeek` is loaded)


         Logging stream for file analysis.

      .. zeek:enum:: Reporter::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/reporter/main.zeek` is loaded)


      .. zeek:enum:: Notice::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/notice/main.zeek` is loaded)


         This is the primary logging stream for notices.

      .. zeek:enum:: Notice::ALARM_LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/notice/main.zeek` is loaded)


         This is the alarm stream.

      .. zeek:enum:: Weird::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/notice/weird.zeek` is loaded)


      .. zeek:enum:: Signatures::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/signatures/main.zeek` is loaded)


      .. zeek:enum:: PacketFilter::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/packet-filter/main.zeek` is loaded)


      .. zeek:enum:: Software::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/software/main.zeek` is loaded)


      .. zeek:enum:: Intel::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/intel/main.zeek` is loaded)


      .. zeek:enum:: Tunnel::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/tunnels/main.zeek` is loaded)


      .. zeek:enum:: OpenFlow::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/openflow/plugins/log.zeek` is loaded)


      .. zeek:enum:: NetControl::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/netcontrol/main.zeek` is loaded)


      .. zeek:enum:: NetControl::DROP_LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/netcontrol/drop.zeek` is loaded)


      .. zeek:enum:: NetControl::SHUNT Log::ID

         (present if :doc:`/scripts/base/frameworks/netcontrol/shunt.zeek` is loaded)


      .. zeek:enum:: Conn::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/conn/main.zeek` is loaded)


      .. zeek:enum:: DCE_RPC::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/dce-rpc/main.zeek` is loaded)


      .. zeek:enum:: DHCP::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/dhcp/main.zeek` is loaded)


      .. zeek:enum:: DNP3::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/dnp3/main.zeek` is loaded)


      .. zeek:enum:: DNS::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/dns/main.zeek` is loaded)


      .. zeek:enum:: FTP::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/ftp/main.zeek` is loaded)


      .. zeek:enum:: SSL::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/ssl/main.zeek` is loaded)


      .. zeek:enum:: X509::LOG Log::ID

         (present if :doc:`/scripts/base/files/x509/main.zeek` is loaded)


      .. zeek:enum:: OCSP::LOG Log::ID

         (present if :doc:`/scripts/base/files/x509/log-ocsp.zeek` is loaded)


      .. zeek:enum:: HTTP::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/http/main.zeek` is loaded)


      .. zeek:enum:: IRC::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/irc/main.zeek` is loaded)


      .. zeek:enum:: KRB::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/krb/main.zeek` is loaded)


      .. zeek:enum:: LDAP::LDAP_LOG Log::ID

         (present if :doc:`/scripts/base/protocols/ldap/main.zeek` is loaded)


      .. zeek:enum:: LDAP::LDAP_SEARCH_LOG Log::ID

         (present if :doc:`/scripts/base/protocols/ldap/main.zeek` is loaded)


      .. zeek:enum:: Modbus::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/modbus/main.zeek` is loaded)


      .. zeek:enum:: MQTT::CONNECT_LOG Log::ID

         (present if :doc:`/scripts/base/protocols/mqtt/main.zeek` is loaded)


      .. zeek:enum:: MQTT::SUBSCRIBE_LOG Log::ID

         (present if :doc:`/scripts/base/protocols/mqtt/main.zeek` is loaded)


      .. zeek:enum:: MQTT::PUBLISH_LOG Log::ID

         (present if :doc:`/scripts/base/protocols/mqtt/main.zeek` is loaded)


      .. zeek:enum:: mysql::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/mysql/main.zeek` is loaded)


      .. zeek:enum:: NTLM::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/ntlm/main.zeek` is loaded)


      .. zeek:enum:: NTP::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/ntp/main.zeek` is loaded)


      .. zeek:enum:: QUIC::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/quic/main.zeek` is loaded)


      .. zeek:enum:: RADIUS::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/radius/main.zeek` is loaded)


      .. zeek:enum:: RDP::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/rdp/main.zeek` is loaded)


      .. zeek:enum:: RFB::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/rfb/main.zeek` is loaded)


      .. zeek:enum:: SIP::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/sip/main.zeek` is loaded)


      .. zeek:enum:: SNMP::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/snmp/main.zeek` is loaded)


      .. zeek:enum:: SMB::MAPPING_LOG Log::ID

         (present if :doc:`/scripts/base/protocols/smb/main.zeek` is loaded)


      .. zeek:enum:: SMB::FILES_LOG Log::ID

         (present if :doc:`/scripts/base/protocols/smb/main.zeek` is loaded)


      .. zeek:enum:: SMTP::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/smtp/main.zeek` is loaded)


      .. zeek:enum:: SOCKS::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/socks/main.zeek` is loaded)


      .. zeek:enum:: SSH::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/ssh/main.zeek` is loaded)


      .. zeek:enum:: Syslog::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/syslog/main.zeek` is loaded)


      .. zeek:enum:: WebSocket::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/websocket/main.zeek` is loaded)


      .. zeek:enum:: PE::LOG Log::ID

         (present if :doc:`/scripts/base/files/pe/main.zeek` is loaded)


      .. zeek:enum:: Management::Log::LOG Log::ID

         (present if :doc:`/scripts/policy/frameworks/management/log.zeek` is loaded)


      .. zeek:enum:: NetControl::CATCH_RELEASE Log::ID

         (present if :doc:`/scripts/policy/frameworks/netcontrol/catch-and-release.zeek` is loaded)


      .. zeek:enum:: Telemetry::LOG Log::ID

         (present if :doc:`/scripts/policy/frameworks/telemetry/log.zeek` is loaded)


      .. zeek:enum:: Telemetry::LOG_HISTOGRAM Log::ID

         (present if :doc:`/scripts/policy/frameworks/telemetry/log.zeek` is loaded)


      .. zeek:enum:: CaptureLoss::LOG Log::ID

         (present if :doc:`/scripts/policy/misc/capture-loss.zeek` is loaded)


      .. zeek:enum:: Traceroute::LOG Log::ID

         (present if :doc:`/scripts/policy/misc/detect-traceroute/main.zeek` is loaded)


      .. zeek:enum:: LoadedScripts::LOG Log::ID

         (present if :doc:`/scripts/policy/misc/loaded-scripts.zeek` is loaded)


      .. zeek:enum:: Stats::LOG Log::ID

         (present if :doc:`/scripts/policy/misc/stats.zeek` is loaded)


      .. zeek:enum:: WeirdStats::LOG Log::ID

         (present if :doc:`/scripts/policy/misc/weird-stats.zeek` is loaded)


      .. zeek:enum:: UnknownProtocol::LOG Log::ID

         (present if :doc:`/scripts/policy/misc/unknown-protocols.zeek` is loaded)


      .. zeek:enum:: Known::HOSTS_LOG Log::ID

         (present if :doc:`/scripts/policy/protocols/conn/known-hosts.zeek` is loaded)


      .. zeek:enum:: Known::SERVICES_LOG Log::ID

         (present if :doc:`/scripts/policy/protocols/conn/known-services.zeek` is loaded)


      .. zeek:enum:: Known::MODBUS_LOG Log::ID

         (present if :doc:`/scripts/policy/protocols/modbus/known-masters-slaves.zeek` is loaded)


      .. zeek:enum:: Modbus::REGISTER_CHANGE_LOG Log::ID

         (present if :doc:`/scripts/policy/protocols/modbus/track-memmap.zeek` is loaded)


      .. zeek:enum:: SMB::CMD_LOG Log::ID

         (present if :doc:`/scripts/policy/protocols/smb/log-cmds.zeek` is loaded)


      .. zeek:enum:: Known::CERTS_LOG Log::ID

         (present if :doc:`/scripts/policy/protocols/ssl/known-certs.zeek` is loaded)


      .. zeek:enum:: ZeekygenExample::LOG Log::ID

         (present if :doc:`/scripts/zeekygen/example.zeek` is loaded)


   Type that defines an ID unique to each log stream. Scripts creating new
   log streams need to redef this enum to add their own specific log ID.
   The log ID implicitly determines the default name of the generated log
   file.

.. zeek:type:: Log::PolicyHook
   :source-code: base/frameworks/logging/main.zeek 353 353

   :Type: :zeek:type:`hook` (rec: :zeek:type:`any`, id: :zeek:type:`Log::ID`, filter: :zeek:type:`Log::Filter`) : :zeek:type:`bool`

   A hook type to implement filtering policy at log filter
   granularity. Like :zeek:see:`Log::StreamPolicyHook`, these can
   implement added functionality, alter it prior to logging, or
   veto the write. These hooks run at log filter granularity,
   so get a :zeek:see:`Log::Filter` instance as additional
   argument. You can pass additional state into the hook via the
   the filter$config table.
   

   :param rec: An instance of the stream's ``columns`` type with its
        fields set to the values to be logged.
   

   :param id: The ID associated with the logging stream the filter
       belongs to.
   

   :param filter: The :zeek:type:`Log::Filter` instance that steers
           the output of the given log record.

.. zeek:type:: Log::PostDelayCallback
   :source-code: base/frameworks/logging/main.zeek 642 642

   :Type: :zeek:type:`function` (rec: :zeek:type:`any`, id: :zeek:type:`Log::ID`) : :zeek:type:`bool`

   Type of function to invoke when delaying a log write has completed.
   
   Functions of this type take the same arguments as :zeek:see:`Log::StreamPolicyHook`
   and act as a callback passed to zeek:see:`Log::delay`. They execute
   just before the record is forwarded to the individual log filters.
   
   Returning ``F`` from a post delay callback discards the log write.

.. zeek:type:: Log::PrintLogInfo
   :source-code: base/frameworks/logging/main.zeek 75 80

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         The network time at which the print statement was executed.

      vals: :zeek:type:`string_vec` :zeek:attr:`&log`
         Set of strings passed to the print statement.

   If :zeek:see:`Log::print_to_log` is set to redirect, ``print`` statements will
   automatically populate log entries with the fields contained in this record.

.. zeek:type:: Log::PrintLogType
   :source-code: base/frameworks/logging/main.zeek 83 83

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Log::REDIRECT_NONE Log::PrintLogType

         No redirection of ``print`` statements.

      .. zeek:enum:: Log::REDIRECT_STDOUT Log::PrintLogType

         Redirection of those ``print`` statements that were being logged to stdout,
         leaving behind those set to go to other specific files.

      .. zeek:enum:: Log::REDIRECT_ALL Log::PrintLogType

         Redirection of all ``print`` statements.

   Configurations for :zeek:see:`Log::print_to_log`

.. zeek:type:: Log::RotationFmtInfo
   :source-code: base/frameworks/logging/main.zeek 120 128

   :Type: :zeek:type:`record`

      writer: :zeek:type:`Log::Writer`
         The log writer being used.

      path: :zeek:type:`string`
         Original path value.

      open: :zeek:type:`time`
         Time when opened.

      close: :zeek:type:`time`
         Time when closed.

      terminating: :zeek:type:`bool`
         True if rotation occurred due to Zeek shutting down.

      postprocessor: :zeek:type:`Log::RotationPostProcessorFunc` :zeek:attr:`&optional`
         The postprocessor function that will be called after rotation.

   Information passed into rotation format callback function given by
   :zeek:see:`Log::rotation_format_func`.

.. zeek:type:: Log::RotationInfo
   :source-code: base/frameworks/logging/main.zeek 106 113

   :Type: :zeek:type:`record`

      writer: :zeek:type:`Log::Writer`
         The log writer being used.

      fname: :zeek:type:`string`
         Full name of the rotated file.

      path: :zeek:type:`string`
         Original path value.

      open: :zeek:type:`time`
         Time when opened.

      close: :zeek:type:`time`
         Time when closed.

      terminating: :zeek:type:`bool`
         True if rotation occurred due to Zeek shutting down.

   Information passed into rotation callback functions.

.. zeek:type:: Log::RotationPath
   :source-code: base/frameworks/logging/main.zeek 145 163

   :Type: :zeek:type:`record`

      dir: :zeek:type:`string` :zeek:attr:`&default` = :zeek:see:`Log::default_rotation_dir` :zeek:attr:`&optional`
         A directory to rotate the log to.  This directory is created
         just-in-time, as the log rotation is about to happen.  If it
         cannot be created, an error is emitted and the rotation process
         tries to proceed with rotation inside the working directory.  When
         setting this field, beware that renaming files across file systems
         will generally fail.

      file_basename: :zeek:type:`string`
         A base name to use for the rotated log.  Log writers may later
         append a file extension of their choosing to this user-chosen
         base (e.g. if using the default ASCII writer and you want
         rotated files of the format "foo-<date>.log", then this basename
         can be set to "foo-<date>" and the ".log" is added later (there's
         also generally means of customizing the file extension, too,
         like the ``ZEEK_LOG_SUFFIX`` environment variable or
         writer-dependent configuration options.

   A log file rotation path specification that's returned by the
   user-customizable :zeek:see:`Log::rotation_format_func`.

.. zeek:type:: Log::RotationPostProcessorFunc
   :source-code: base/frameworks/logging/main.zeek 116 116

   :Type: :zeek:type:`function` (info: :zeek:type:`Log::RotationInfo`) : :zeek:type:`bool`

   The function type for log rotation post processors.

.. zeek:type:: Log::Stream
   :source-code: base/frameworks/logging/main.zeek 370 425

   :Type: :zeek:type:`record`

      columns: :zeek:type:`any`
         A record type defining the log's columns.

      ev: :zeek:type:`any` :zeek:attr:`&optional`
         Event that will be raised once for each log entry.
         The event receives a single same parameter, an instance of
         type ``columns``.

      path: :zeek:type:`string` :zeek:attr:`&optional`
         A path that will be inherited by any filters added to the
         stream which do not already specify their own path.

      policy: :zeek:type:`Log::PolicyHook` :zeek:attr:`&optional`
         Policy hooks can adjust log records and veto their
         writing. Any hook handler that breaks from its body
         signals that Zeek won't log the entry passed into
         it. You can pass arbitrary state into the hook via
         the filter instance and its config table.
         
         New Filters created for this stream will inherit
         this policy hook, unless they provide their own.

      event_groups: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         Event groups associated with this stream that are disabled
         when :zeek:see:`Log::disable_stream` is invoked and
         re-enabled during :zeek:see:`Log::enable_stream`.
         
         This field can be used to short-circuit event handlers that
         are solely responsible for logging functionality at runtime
         when a log stream is disabled.
         
         This field allows for both, attribute event groups and module
         event groups. If the given group names exists as attribute
         or module or either event group, they are disabled when the
         log stream is disabled and enabled when the stream is
         enabled again.

      max_delay_interval: :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Log::default_max_delay_interval` :zeek:attr:`&optional`
         Maximum delay interval for this stream.
         
         This value can be increased using :zeek:see:`Log::set_max_delay_interval`
         after the stream has been created.
         
         .. :zeek:see:`Log::default_max_delay_interval`
         .. :zeek:see:`Log::set_max_delay_interval`

      max_delay_queue_size: :zeek:type:`count` :zeek:attr:`&default` = :zeek:see:`Log::default_max_delay_queue_size` :zeek:attr:`&optional`
         Maximum delay queue size of this stream.
         
         This value can be changed using :zeek:see:`Log::set_max_delay_queue_size`
         after the stream has been created.
         
         .. :zeek:see:`Log::default_max_delay_queue_size`
         .. :zeek:see:`Log::set_max_delay_queue_size`

   Type defining the content of a logging stream.

.. zeek:type:: Log::StreamPolicyHook
   :source-code: base/frameworks/logging/main.zeek 335 335

   :Type: :zeek:type:`hook` (rec: :zeek:type:`any`, id: :zeek:type:`Log::ID`) : :zeek:type:`bool`

   A hook type to implement filtering policy. Hook handlers run
   on each log record. They can implement arbitrary per-record
   processing, alter the log record, or veto the writing of the
   given record by breaking from the hook handler.
   

   :param rec: An instance of the stream's ``columns`` type with its
        fields set to the values to be logged.
   

   :param id: The ID associated with the logging stream the filter
       belongs to.

.. zeek:type:: Log::Writer

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Log::WRITER_ASCII Log::Writer

      .. zeek:enum:: Log::WRITER_NONE Log::Writer

      .. zeek:enum:: Log::WRITER_SQLITE Log::Writer


Events
######
.. zeek:id:: Log::log_print
   :source-code: base/frameworks/logging/main.zeek 94 94

   :Type: :zeek:type:`event` (rec: :zeek:type:`Log::PrintLogInfo`)

   Event for accessing logged print records.

Hooks
#####
.. zeek:id:: Log::log_stream_policy
   :source-code: base/frameworks/logging/main.zeek 633 633

   :Type: :zeek:type:`Log::StreamPolicyHook`

   The global log policy hook. The framework invokes this hook for any
   log write, prior to iterating over the stream's associated filters.
   As with filter-specific hooks, breaking from the hook vetoes writing
   of the given log record. Note that filter-level policy hooks still get
   invoked after the global hook vetoes, but they cannot "un-veto" the write.

Functions
#########
.. zeek:id:: Log::add_default_filter
   :source-code: base/frameworks/logging/main.zeek 998 1001

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`

   Adds a default :zeek:type:`Log::Filter` record with ``name`` field
   set as "default" to a given logging stream.
   

   :param id: The ID associated with a logging stream for which to add a default
       filter.
   

   :returns: The status of a call to :zeek:id:`Log::add_filter` using a
            default :zeek:type:`Log::Filter` argument with ``name`` field
            set to "default".
   
   .. zeek:see:: Log::add_filter Log::remove_filter
      Log::remove_default_filter

.. zeek:id:: Log::add_filter
   :source-code: base/frameworks/logging/main.zeek 938 955

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, filter: :zeek:type:`Log::Filter`) : :zeek:type:`bool`

   Adds a custom filter to an existing logging stream.  If a filter
   with a matching ``name`` field already exists for the stream, it
   is removed when the new filter is successfully added.
   

   :param id: The ID associated with the logging stream to filter.
   

   :param filter: A record describing the desired logging parameters.
   

   :returns: True if the filter was successfully added, false if
            the filter was not added or the *filter* argument was not
            the correct type.
   
   .. zeek:see:: Log::remove_filter Log::add_default_filter
      Log::remove_default_filter Log::get_filter Log::get_filter_names

.. zeek:id:: Log::create_stream
   :source-code: base/frameworks/logging/main.zeek 863 872

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, stream: :zeek:type:`Log::Stream`) : :zeek:type:`bool`

   Creates a new logging stream with the default filter.
   

   :param id: The ID enum to be associated with the new logging stream.
   

   :param stream: A record defining the content that the new stream will log.
   

   :returns: True if a new logging stream was successfully created and
            a default filter added to it.
   
   .. zeek:see:: Log::add_default_filter Log::remove_default_filter

.. zeek:id:: Log::default_ext_func
   :source-code: base/frameworks/logging/main.zeek 216 217

   :Type: :zeek:type:`function` (path: :zeek:type:`string`) : :zeek:type:`any`
   :Attributes: :zeek:attr:`&redef`

   Default log extension function in the case that you would like to
   apply the same extensions to all logs.  The function *must* return
   a record with all of the fields to be included in the log. The
   default function included here does not return a value, which indicates
   that no extensions are added.

.. zeek:id:: Log::default_path_func
   :source-code: base/frameworks/logging/main.zeek 760 796

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, path: :zeek:type:`string`, rec: :zeek:type:`any`) : :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`

   Builds the default path values for log filters if not otherwise
   specified by a filter. The default implementation uses *id*
   to derive a name.  Upon adding a filter to a stream, if neither
   ``path`` nor ``path_func`` is explicitly set by them, then
   this function is used as the ``path_func``.
   

   :param id: The ID associated with the log stream.
   

   :param path: A suggested path value, which may be either the filter's
         ``path`` if defined, else a previous result from the function.
         If no ``path`` is defined for the filter, then the first call
         to the function will contain an empty string.
   

   :param rec: An instance of the stream's ``columns`` type with its
        fields set to the values to be logged.
   

   :returns: The path to be used for the filter.

.. zeek:id:: Log::delay
   :source-code: base/frameworks/logging/main.zeek 1018 1021

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, rec: :zeek:type:`any`, post_delay_cb: :zeek:type:`Log::PostDelayCallback` :zeek:attr:`&default` = :zeek:see:`Log::empty_post_delay_cb` :zeek:attr:`&optional`) : :zeek:type:`Log::DelayToken`

   Delay a log write.
   
   Calling this function is currently only allowed within the execution
   of a :zeek:see:`Log::log_stream_policy` hook and requires the caller
   to provide the stream ID and log record of the active write operation
   as parameters.
   
   Conceptually, the delay is inserted between the execution of the

   :param zeek:see:`Log::log_stream_policy` hook and the policy hooks of filters.
   
   Calling this function increments a reference count that can subsequently
   be decremented using :zeek:see:`Log::delay_finish`.
   The delay completes when either the reference count reaches zero, or
   the configured maximum delay interval for the stream expires. The
   optional *post_delay_cb* is invoked when the delay completed.
   
   The *post_delay_cb* function can extend the delay by invoking
   :zeek:see:`Log::delay` again. There's no limit to how often a write
   can be re-delayed. Further, it can discard the log record altogether
   by returning ``F``. If *post_delay_cb* is not provided, the behavior
   is equivalent to a no-op callback solely returning ``T``.
   

   :param id: The ID associated with a logging stream.
   

   :param rec: The log record.
   

   :param post_delay_cb: A callback to invoke when the delay completed.
   

   :returns: An opaque token of type :zeek:see:`Log::DelayToken`
            to be passed to :zeek:see:`Log::delay_finish`.

.. zeek:id:: Log::delay_finish
   :source-code: base/frameworks/logging/main.zeek 1023 1026

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, rec: :zeek:type:`any`, token: :zeek:type:`Log::DelayToken`) : :zeek:type:`bool`

   Release a delay reference taken with :zeek:see:`Log::delay`.
   
   When the last reference is released, :zeek:see:`Log::delay_finish`
   synchronously resumes the delayed :zeek:see:`Log::write` operation.
   

   :param id: The ID associated with a logging stream.
   

   :param rec: The log record.
   

   :param token: The opaque token as returned by :zeek:see:`Log::delay`.
   

   :returns: ``T`` on success, ``F`` if an inconsistent combination of
            *id*, *rec* and *token* was provided.

.. zeek:id:: Log::disable_stream
   :source-code: base/frameworks/logging/main.zeek 889 906

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`

   Disables a currently enabled logging stream.  Disabled streams
   will not be written to until they are enabled again.  New streams
   are enabled by default.
   

   :param id: The ID associated with the logging stream to disable.
   

   :returns: True if the stream is now disabled or was already disabled.
   
   .. zeek:see:: Log::enable_stream

.. zeek:id:: Log::empty_post_delay_cb
   :source-code: base/frameworks/logging/main.zeek 1014 1016

   :Type: :zeek:type:`function` (rec: :zeek:type:`any`, id: :zeek:type:`Log::ID`) : :zeek:type:`bool`

   Represents a post delay callback that simply returns T. This is used
   as a default value for :zeek:see:`Log::delay` and ignored internally.

.. zeek:id:: Log::enable_stream
   :source-code: base/frameworks/logging/main.zeek 908 927

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`

   Enables a previously disabled logging stream.  Disabled streams
   will not be written to until they are enabled again.  New streams
   are enabled by default.
   

   :param id: The ID associated with the logging stream to enable.
   

   :returns: True if the stream is re-enabled or was not previously disabled.
   
   .. zeek:see:: Log::disable_stream

.. zeek:id:: Log::flush
   :source-code: base/frameworks/logging/main.zeek 993 996

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`

   Flushes any currently buffered output for all the writers of a given
   logging stream.
   

   :param id: The ID associated with a logging stream for which to flush buffered
       data.
   

   :returns: True if all writers of a log stream were signalled to flush
            buffered data or if the logging stream is disabled,
            false if the logging stream does not exist.
   
   .. zeek:see:: Log::set_buf Log::enable_stream Log::disable_stream

.. zeek:id:: Log::get_delay_queue_size
   :source-code: base/frameworks/logging/main.zeek 1059 1062

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`int`

   Get the current size of the delay queue for a stream.
   

   :param id: The ID associated with a logging stream.
   

   :returns: The current size of the delay queue, or -1 on error.

.. zeek:id:: Log::get_filter
   :source-code: base/frameworks/logging/main.zeek 967 973

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, name: :zeek:type:`string`) : :zeek:type:`Log::Filter`

   Gets a filter associated with an existing logging stream.
   

   :param id: The ID associated with a logging stream from which to
       obtain one of its filters.
   

   :param name: A string to match against the ``name`` field of a
         :zeek:type:`Log::Filter` for identification purposes.
   

   :returns: A filter attached to the logging stream *id* matching
            *name* or, if no matches are found returns the
            :zeek:id:`Log::no_filter` sentinel value.
   
   .. zeek:see:: Log::add_filter Log::remove_filter Log::add_default_filter
                Log::remove_default_filter Log::get_filter_names

.. zeek:id:: Log::get_filter_names
   :source-code: base/frameworks/logging/main.zeek 975 981

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`set` [:zeek:type:`string`]

   Gets the names of all filters associated with an existing
   logging stream.
   

   :param id: The ID of a logging stream from which to obtain the list
       of filter names.
   

   :returns: The set of filter names associated with the stream.
   
   ..zeek:see:: Log::remove_filter Log::add_default_filter
     Log::remove_default_filter Log::get_filter

.. zeek:id:: Log::remove_default_filter
   :source-code: base/frameworks/logging/main.zeek 1003 1006

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`

   Removes the :zeek:type:`Log::Filter` with ``name`` field equal to
   "default".
   

   :param id: The ID associated with a logging stream from which to remove the
       default filter.
   

   :returns: The status of a call to :zeek:id:`Log::remove_filter` using
            "default" as the argument.
   
   .. zeek:see:: Log::add_filter Log::remove_filter Log::add_default_filter

.. zeek:id:: Log::remove_filter
   :source-code: base/frameworks/logging/main.zeek 957 965

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, name: :zeek:type:`string`) : :zeek:type:`bool`

   Removes a filter from an existing logging stream.
   

   :param id: The ID associated with the logging stream from which to
       remove a filter.
   

   :param name: A string to match against the ``name`` field of a
         :zeek:type:`Log::Filter` for identification purposes.
   

   :returns: True if the logging stream's filter was removed or
            if no filter associated with *name* was found.
   
   .. zeek:see:: Log::remove_filter Log::add_default_filter
      Log::remove_default_filter Log::get_filter Log::get_filter_names

.. zeek:id:: Log::remove_stream
   :source-code: base/frameworks/logging/main.zeek 874 887

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`

   Removes a logging stream completely, stopping all the threads.
   

   :param id: The ID associated with the logging stream.
   

   :returns: True if the stream was successfully removed.
   
   .. zeek:see:: Log::create_stream

.. zeek:id:: Log::rotation_format_func
   :source-code: base/frameworks/logging/main.zeek 836 861

   :Type: :zeek:type:`function` (ri: :zeek:type:`Log::RotationFmtInfo`) : :zeek:type:`Log::RotationPath`
   :Attributes: :zeek:attr:`&redef`

   A function that one may use to customize log file rotation paths.

.. zeek:id:: Log::run_rotation_postprocessor_cmd
   :source-code: base/frameworks/logging/main.zeek 799 822

   :Type: :zeek:type:`function` (info: :zeek:type:`Log::RotationInfo`, npath: :zeek:type:`string`) : :zeek:type:`bool`

   Runs a command given by :zeek:id:`Log::default_rotation_postprocessor_cmd`
   on a rotated file.  Meant to be called from postprocessor functions
   that are added to :zeek:id:`Log::default_rotation_postprocessors`.
   

   :param info: A record holding meta-information about the log being rotated.
   

   :param npath: The new path of the file (after already being rotated/processed
          by writer-specific postprocessor as defined in
          :zeek:id:`Log::default_rotation_postprocessors`).
   

   :returns: True when :zeek:id:`Log::default_rotation_postprocessor_cmd`
            is empty or the system command given by it has been invoked
            to postprocess a rotated log file.
   
   .. zeek:see:: Log::default_rotation_date_format
      Log::default_rotation_postprocessor_cmd_env
      Log::default_rotation_postprocessor_cmd
      Log::default_rotation_postprocessors

.. zeek:id:: Log::set_buf
   :source-code: base/frameworks/logging/main.zeek 988 991

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, buffered: :zeek:type:`bool`) : :zeek:type:`bool`

   Sets the buffering status for all the writers of a given logging stream.
   A given writer implementation may or may not support buffering and if
   it doesn't then toggling buffering with this function has no effect.
   

   :param id: The ID associated with a logging stream for which to
       enable/disable buffering.
   

   :param buffered: Whether to enable or disable log buffering.
   

   :returns: True if buffering status was set, false if the logging stream
            does not exist.
   
   .. zeek:see:: Log::flush

.. zeek:id:: Log::set_max_delay_interval
   :source-code: base/frameworks/logging/main.zeek 1028 1044

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, max_delay: :zeek:type:`interval`) : :zeek:type:`bool`

   Set the maximum delay for a stream.
   
   Multiple calls to this function will only ever increase the maximum
   delay, the delay cannot be lowered. The default maximum delay for a
   stream is zeek:see:`Log::default_max_delay_interval`.
   
   When a stream is removed and re-created via :zeek:see:`Log::create_stream`,
   the new stream is re-configured with the previously used maximum delay.
   

   :param id: The ID associated with a logging stream.
   

   :param max_delay: The maximum delay interval for this stream.
   

   :returns: ``T`` on success, else ``F``.

.. zeek:id:: Log::set_max_delay_queue_size
   :source-code: base/frameworks/logging/main.zeek 1046 1057

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, max_size: :zeek:type:`count`) : :zeek:type:`bool`

   Set the given stream's delay queue size.
   
   If the queue holds more records than the given *queue_size*, these are
   attempted to be evicted at the time of the call.
   
   When a stream is removed and re-created via :zeek:see:`Log::create_stream`,
   the new stream is re-configured with the most recently used queue size.
   

   :param id: The ID associated with a logging stream.
   

   :param max_delay: The maximum delay interval of this stream.
   

   :returns: ``T`` on success, else ``F``.

.. zeek:id:: Log::write
   :source-code: base/frameworks/logging/main.zeek 983 986

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, columns: :zeek:type:`any`) : :zeek:type:`bool`

   Writes a new log line/entry to a logging stream.
   

   :param id: The ID associated with a logging stream to be written to.
   

   :param columns: A record value describing the values of each field/column
            to write to the log stream.
   

   :returns: True if the stream was found and no error occurred in writing
            to it or if the stream was disabled and nothing was written.
            False if the stream was not found, or the *columns*
            argument did not match what the stream was initially defined
            to handle, or one of the stream's filters has an invalid
            ``path_func``.
   
   .. zeek:see:: Log::enable_stream Log::disable_stream


