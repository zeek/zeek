:tocdepth: 3

base/frameworks/logging/main.bro
================================
.. bro:namespace:: Log

The Bro logging interface.

See :doc:`/frameworks/logging` for an introduction to Bro's
logging framework.

:Namespace: Log
:Imports: :doc:`base/bif/logging.bif.bro </scripts/base/bif/logging.bif.bro>`

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================== =====================================================================
:bro:id:`Log::default_ext_prefix`: :bro:type:`string` :bro:attr:`&redef`                 A prefix for extension fields which can be optionally prefixed
                                                                                         on all log lines by setting the `ext_func` field in the
                                                                                         log filter.
:bro:id:`Log::default_field_name_map`: :bro:type:`table` :bro:attr:`&redef`              Default field name mapping for renaming fields in a logging framework
                                                                                         filter.
:bro:id:`Log::default_mail_alarms_interval`: :bro:type:`interval` :bro:attr:`&redef`     Default alarm summary mail interval.
:bro:id:`Log::default_rotation_date_format`: :bro:type:`string` :bro:attr:`&redef`       Default naming format for timestamps embedded into filenames.
:bro:id:`Log::default_rotation_interval`: :bro:type:`interval` :bro:attr:`&redef`        Default rotation interval to use for filters that do not specify
                                                                                         an interval.
:bro:id:`Log::default_rotation_postprocessor_cmd`: :bro:type:`string` :bro:attr:`&redef` Default shell command to run on rotated files.
:bro:id:`Log::default_rotation_postprocessors`: :bro:type:`table` :bro:attr:`&redef`     Specifies the default postprocessor function per writer type.
:bro:id:`Log::default_scope_sep`: :bro:type:`string` :bro:attr:`&redef`                  Default separator for log field scopes when logs are unrolled and
                                                                                         flattened.
:bro:id:`Log::default_writer`: :bro:type:`Log::Writer` :bro:attr:`&redef`                Default writer to use if a filter does not specify anything else.
:bro:id:`Log::empty_field`: :bro:type:`string` :bro:attr:`&redef`                        Default string to use for empty fields.
:bro:id:`Log::enable_local_logging`: :bro:type:`bool` :bro:attr:`&redef`                 If true, local logging is by default enabled for all filters.
:bro:id:`Log::enable_remote_logging`: :bro:type:`bool` :bro:attr:`&redef`                If true, remote logging is by default enabled for all filters.
:bro:id:`Log::separator`: :bro:type:`string` :bro:attr:`&redef`                          Default separator to use between fields.
:bro:id:`Log::set_separator`: :bro:type:`string` :bro:attr:`&redef`                      Default separator to use between elements of a set.
:bro:id:`Log::unset_field`: :bro:type:`string` :bro:attr:`&redef`                        Default string to use for an unset &optional field.
======================================================================================== =====================================================================

Constants
#########
================================================= =========================================================================
:bro:id:`Log::no_filter`: :bro:type:`Log::Filter` Sentinel value for indicating that a filter was not found when looked up.
================================================= =========================================================================

State Variables
###############
================================================ ========================================================
:bro:id:`Log::active_streams`: :bro:type:`table` The streams which are currently active and not disabled.
================================================ ========================================================

Types
#####
================================================= =========================================================
:bro:type:`Log::Filter`: :bro:type:`record`       A filter type describes how to customize logging streams.
:bro:type:`Log::ID`: :bro:type:`enum`             Type that defines an ID unique to each log stream.
:bro:type:`Log::RotationInfo`: :bro:type:`record` Information passed into rotation callback functions.
:bro:type:`Log::Stream`: :bro:type:`record`       Type defining the content of a logging stream.
:bro:type:`Log::Writer`: :bro:type:`enum`         
================================================= =========================================================

Functions
#########
========================================================================= =========================================================================
:bro:id:`Log::add_default_filter`: :bro:type:`function`                   Adds a default :bro:type:`Log::Filter` record with ``name`` field
                                                                          set as "default" to a given logging stream.
:bro:id:`Log::add_filter`: :bro:type:`function`                           Adds a custom filter to an existing logging stream.
:bro:id:`Log::create_stream`: :bro:type:`function`                        Creates a new logging stream with the default filter.
:bro:id:`Log::default_ext_func`: :bro:type:`function` :bro:attr:`&redef`  Default log extension function in the case that you would like to
                                                                          apply the same extensions to all logs.
:bro:id:`Log::default_path_func`: :bro:type:`function` :bro:attr:`&redef` Builds the default path values for log filters if not otherwise
                                                                          specified by a filter.
:bro:id:`Log::disable_stream`: :bro:type:`function`                       Disables a currently enabled logging stream.
:bro:id:`Log::enable_stream`: :bro:type:`function`                        Enables a previously disabled logging stream.
:bro:id:`Log::flush`: :bro:type:`function`                                Flushes any currently buffered output for all the writers of a given
                                                                          logging stream.
:bro:id:`Log::get_filter`: :bro:type:`function`                           Gets a filter associated with an existing logging stream.
:bro:id:`Log::get_filter_names`: :bro:type:`function`                     Gets the names of all filters associated with an existing
                                                                          logging stream.
:bro:id:`Log::remove_default_filter`: :bro:type:`function`                Removes the :bro:type:`Log::Filter` with ``name`` field equal to
                                                                          "default".
:bro:id:`Log::remove_filter`: :bro:type:`function`                        Removes a filter from an existing logging stream.
:bro:id:`Log::remove_stream`: :bro:type:`function`                        Removes a logging stream completely, stopping all the threads.
:bro:id:`Log::run_rotation_postprocessor_cmd`: :bro:type:`function`       Runs a command given by :bro:id:`Log::default_rotation_postprocessor_cmd`
                                                                          on a rotated file.
:bro:id:`Log::set_buf`: :bro:type:`function`                              Sets the buffering status for all the writers of a given logging stream.
:bro:id:`Log::write`: :bro:type:`function`                                Writes a new log line/entry to a logging stream.
========================================================================= =========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: Log::default_ext_prefix

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"_"``

   A prefix for extension fields which can be optionally prefixed
   on all log lines by setting the `ext_func` field in the
   log filter.

.. bro:id:: Log::default_field_name_map

   :Type: :bro:type:`table` [:bro:type:`string`] of :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Default field name mapping for renaming fields in a logging framework
   filter.  This is typically used to ease integration with external
   data storage and analysis systems.

.. bro:id:: Log::default_mail_alarms_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0 secs``

   Default alarm summary mail interval. Zero disables alarm summary
   mails.
   
   Note that this is overridden by the BroControl MailAlarmsInterval
   option.

.. bro:id:: Log::default_rotation_date_format

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"%Y-%m-%d-%H-%M-%S"``

   Default naming format for timestamps embedded into filenames.
   Uses a ``strftime()`` style.

.. bro:id:: Log::default_rotation_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``0 secs``

   Default rotation interval to use for filters that do not specify
   an interval. Zero disables rotation.
   
   Note that this is overridden by the BroControl LogRotationInterval
   option.

.. bro:id:: Log::default_rotation_postprocessor_cmd

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Default shell command to run on rotated files. Empty for none.

.. bro:id:: Log::default_rotation_postprocessors

   :Type: :bro:type:`table` [:bro:type:`Log::Writer`] of :bro:type:`function` (info: :bro:type:`Log::RotationInfo`) : :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         [Log::WRITER_NONE] = LogNone::default_rotation_postprocessor_func
         { 
         return (T);
         },
         [Log::WRITER_ASCII] = LogAscii::default_rotation_postprocessor_func
         { 
         LogAscii::gz = LogAscii::info$fname[-3, (coerce flattenLogAscii::info$fname to int)] == ".gz" ? ".gz" : "";
         LogAscii::bls = getenv("BRO_LOG_SUFFIX");
         if ("" == LogAscii::bls) 
            LogAscii::bls = "log";

         LogAscii::dst = fmt("%s.%s.%s%s", LogAscii::info$path, strftime(Log::default_rotation_date_format, LogAscii::info$open), LogAscii::bls, LogAscii::gz);
         system(fmt("/bin/mv %s %s", LogAscii::info$fname, LogAscii::dst));
         return (Log::run_rotation_postprocessor_cmd(LogAscii::info, LogAscii::dst));
         }
      }

   Specifies the default postprocessor function per writer type.
   Entries in this table are initialized by each writer type.

.. bro:id:: Log::default_scope_sep

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"."``

   Default separator for log field scopes when logs are unrolled and
   flattened.  This will be the string between field name components.
   For example, setting this to "_" will cause the typical field
   "id.orig_h" to turn into "id_orig_h".

.. bro:id:: Log::default_writer

   :Type: :bro:type:`Log::Writer`
   :Attributes: :bro:attr:`&redef`
   :Default: ``Log::WRITER_ASCII``

   Default writer to use if a filter does not specify anything else.

.. bro:id:: Log::empty_field

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"(empty)"``

   Default string to use for empty fields. This should be different
   from *unset_field* to make the output unambiguous.
   Individual writers can use a different value.

.. bro:id:: Log::enable_local_logging

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   If true, local logging is by default enabled for all filters.

.. bro:id:: Log::enable_remote_logging

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   If true, remote logging is by default enabled for all filters.

.. bro:id:: Log::separator

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"\x09"``

   Default separator to use between fields.
   Individual writers can use a different value.

.. bro:id:: Log::set_separator

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``","``

   Default separator to use between elements of a set.
   Individual writers can use a different value.

.. bro:id:: Log::unset_field

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"-"``

   Default string to use for an unset &optional field.
   Individual writers can use a different value.

Constants
#########
.. bro:id:: Log::no_filter

   :Type: :bro:type:`Log::Filter`
   :Default:

   ::

      {
         name="<not found>"
         writer=Log::WRITER_ASCII
         pred=<uninitialized>
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
         ext_func=anonymous-function
         ;
         interv=0 secs
         postprocessor=<uninitialized>
         config={

         }
      }

   Sentinel value for indicating that a filter was not found when looked up.

State Variables
###############
.. bro:id:: Log::active_streams

   :Type: :bro:type:`table` [:bro:type:`Log::ID`] of :bro:type:`Log::Stream`
   :Default: ``{}``

   The streams which are currently active and not disabled.
   This table is not meant to be modified by users!  Only use it for
   examining which streams are active.

Types
#####
.. bro:type:: Log::Filter

   :Type: :bro:type:`record`

      name: :bro:type:`string`
         Descriptive name to reference this filter.

      writer: :bro:type:`Log::Writer` :bro:attr:`&default` = :bro:see:`Log::default_writer` :bro:attr:`&optional`
         The logging writer implementation to use.

      pred: :bro:type:`function` (rec: :bro:type:`any`) : :bro:type:`bool` :bro:attr:`&optional`
         Indicates whether a log entry should be recorded.
         If not given, all entries are recorded.
         

         :rec: An instance of the stream's ``columns`` type with its
              fields set to the values to be logged.
         

         :returns: True if the entry is to be recorded.

      path: :bro:type:`string` :bro:attr:`&optional`
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

      path_func: :bro:type:`function` (id: :bro:type:`Log::ID`, path: :bro:type:`string`, rec: :bro:type:`any`) : :bro:type:`string` :bro:attr:`&optional`
         A function returning the output path for recording entries
         matching this filter. This is similar to *path* yet allows
         to compute the string dynamically. It is ok to return
         different strings for separate calls, but be careful: it's
         easy to flood the disk by returning a new string for each
         connection.  Upon adding a filter to a stream, if neither
         ``path`` nor ``path_func`` is explicitly set by them, then
         :bro:see:`Log::default_path_func` is used.
         

         :id: The ID associated with the log stream.
         

         :path: A suggested path value, which may be either the filter's
               ``path`` if defined, else a previous result from the
               function.  If no ``path`` is defined for the filter,
               then the first call to the function will contain an
               empty string.
         

         :rec: An instance of the stream's ``columns`` type with its
              fields set to the values to be logged.
         

         :returns: The path to be used for the filter, which will be
                  subject to the same automatic correction rules as
                  the *path* field of :bro:type:`Log::Filter` in the
                  case of conflicts with other filters trying to use
                  the same writer/path pair.

      include: :bro:type:`set` [:bro:type:`string`] :bro:attr:`&optional`
         Subset of column names to record. If not given, all
         columns are recorded.

      exclude: :bro:type:`set` [:bro:type:`string`] :bro:attr:`&optional`
         Subset of column names to exclude from recording. If not
         given, all columns are recorded.

      log_local: :bro:type:`bool` :bro:attr:`&default` = :bro:see:`Log::enable_local_logging` :bro:attr:`&optional`
         If true, entries are recorded locally.

      log_remote: :bro:type:`bool` :bro:attr:`&default` = :bro:see:`Log::enable_remote_logging` :bro:attr:`&optional`
         If true, entries are passed on to remote peers.

      field_name_map: :bro:type:`table` [:bro:type:`string`] of :bro:type:`string` :bro:attr:`&default` = :bro:see:`Log::default_field_name_map` :bro:attr:`&optional`
         Field name map to rename fields before the fields are written
         to the output.

      scope_sep: :bro:type:`string` :bro:attr:`&default` = :bro:see:`Log::default_scope_sep` :bro:attr:`&optional`
         A string that is used for unrolling and flattening field names
         for nested record types.

      ext_prefix: :bro:type:`string` :bro:attr:`&default` = :bro:see:`Log::default_ext_prefix` :bro:attr:`&optional`
         Default prefix for all extension fields. It's typically
         prudent to set this to something that Bro's logging
         framework can't normally write out in a field name.

      ext_func: :bro:type:`function` (path: :bro:type:`string`) : :bro:type:`any` :bro:attr:`&default` = :bro:see:`Log::default_ext_func` :bro:attr:`&optional`
         Function to collect a log extension value.  If not specified,
         no log extension will be provided for the log.
         The return value from the function *must* be a record.

      interv: :bro:type:`interval` :bro:attr:`&default` = :bro:see:`Log::default_rotation_interval` :bro:attr:`&optional`
         Rotation interval. Zero disables rotation.

      postprocessor: :bro:type:`function` (info: :bro:type:`Log::RotationInfo`) : :bro:type:`bool` :bro:attr:`&optional`
         Callback function to trigger for rotated files. If not set, the
         default comes out of :bro:id:`Log::default_rotation_postprocessors`.

      config: :bro:type:`table` [:bro:type:`string`] of :bro:type:`string` :bro:attr:`&default` = ``{  }`` :bro:attr:`&optional`
         A key/value table that will be passed on to the writer.
         Interpretation of the values is left to the writer, but
         usually they will be used for configuration purposes.

   A filter type describes how to customize logging streams.

.. bro:type:: Log::ID

   :Type: :bro:type:`enum`

      .. bro:enum:: Log::UNKNOWN Log::ID

         Dummy place-holder.

      .. bro:enum:: Broker::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/broker/log.bro` is loaded)


      .. bro:enum:: Files::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/files/main.bro` is loaded)


         Logging stream for file analysis.

      .. bro:enum:: Reporter::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/reporter/main.bro` is loaded)


      .. bro:enum:: Cluster::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/cluster/main.bro` is loaded)


      .. bro:enum:: Notice::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/notice/main.bro` is loaded)


         This is the primary logging stream for notices.

      .. bro:enum:: Notice::ALARM_LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/notice/main.bro` is loaded)


         This is the alarm stream.

      .. bro:enum:: Weird::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/notice/weird.bro` is loaded)


      .. bro:enum:: NetControl::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/netcontrol/main.bro` is loaded)


      .. bro:enum:: OpenFlow::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/openflow/plugins/log.bro` is loaded)


      .. bro:enum:: NetControl::DROP Log::ID

         (present if :doc:`/scripts/base/frameworks/netcontrol/types.bro` is loaded)


         Stop forwarding all packets matching the entity.
         
         No additional arguments.

      .. bro:enum:: NetControl::SHUNT Log::ID

         (present if :doc:`/scripts/base/frameworks/netcontrol/shunt.bro` is loaded)


      .. bro:enum:: NetControl::CATCH_RELEASE Log::ID

         (present if :doc:`/scripts/base/frameworks/netcontrol/catch-and-release.bro` is loaded)


      .. bro:enum:: DPD::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/dpd/main.bro` is loaded)


      .. bro:enum:: Signatures::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/signatures/main.bro` is loaded)


      .. bro:enum:: PacketFilter::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/packet-filter/main.bro` is loaded)


      .. bro:enum:: Software::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/software/main.bro` is loaded)


      .. bro:enum:: Intel::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/intel/main.bro` is loaded)


      .. bro:enum:: Config::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/config/main.bro` is loaded)


      .. bro:enum:: Tunnel::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/tunnels/main.bro` is loaded)


      .. bro:enum:: Conn::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/conn/main.bro` is loaded)


      .. bro:enum:: DCE_RPC::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/dce-rpc/main.bro` is loaded)


      .. bro:enum:: DHCP::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/dhcp/main.bro` is loaded)


      .. bro:enum:: DNP3::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/dnp3/main.bro` is loaded)


      .. bro:enum:: DNS::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/dns/main.bro` is loaded)


      .. bro:enum:: FTP::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/ftp/main.bro` is loaded)


      .. bro:enum:: SSL::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/ssl/main.bro` is loaded)


      .. bro:enum:: X509::LOG Log::ID

         (present if :doc:`/scripts/base/files/x509/main.bro` is loaded)


      .. bro:enum:: HTTP::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/http/main.bro` is loaded)


      .. bro:enum:: IRC::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/irc/main.bro` is loaded)


      .. bro:enum:: KRB::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/krb/main.bro` is loaded)


      .. bro:enum:: Modbus::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/modbus/main.bro` is loaded)


      .. bro:enum:: mysql::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/mysql/main.bro` is loaded)


      .. bro:enum:: NTLM::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/ntlm/main.bro` is loaded)


      .. bro:enum:: RADIUS::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/radius/main.bro` is loaded)


      .. bro:enum:: RDP::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/rdp/main.bro` is loaded)


      .. bro:enum:: RFB::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/rfb/main.bro` is loaded)


      .. bro:enum:: SIP::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/sip/main.bro` is loaded)


      .. bro:enum:: SNMP::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/snmp/main.bro` is loaded)


      .. bro:enum:: SMB::AUTH_LOG Log::ID

         (present if :doc:`/scripts/base/protocols/smb/main.bro` is loaded)


      .. bro:enum:: SMB::MAPPING_LOG Log::ID

         (present if :doc:`/scripts/base/protocols/smb/main.bro` is loaded)


      .. bro:enum:: SMB::FILES_LOG Log::ID

         (present if :doc:`/scripts/base/protocols/smb/main.bro` is loaded)


      .. bro:enum:: SMTP::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/smtp/main.bro` is loaded)


      .. bro:enum:: SOCKS::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/socks/main.bro` is loaded)


      .. bro:enum:: SSH::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/ssh/main.bro` is loaded)


      .. bro:enum:: Syslog::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/syslog/main.bro` is loaded)


      .. bro:enum:: PE::LOG Log::ID

         (present if :doc:`/scripts/base/files/pe/main.bro` is loaded)


      .. bro:enum:: Unified2::LOG Log::ID

         (present if :doc:`/scripts/base/files/unified2/main.bro` is loaded)


      .. bro:enum:: OCSP::LOG Log::ID

         (present if :doc:`/scripts/policy/files/x509/log-ocsp.bro` is loaded)


      .. bro:enum:: Barnyard2::LOG Log::ID

         (present if :doc:`/scripts/policy/integration/barnyard2/main.bro` is loaded)


      .. bro:enum:: CaptureLoss::LOG Log::ID

         (present if :doc:`/scripts/policy/misc/capture-loss.bro` is loaded)


      .. bro:enum:: Traceroute::LOG Log::ID

         (present if :doc:`/scripts/policy/misc/detect-traceroute/main.bro` is loaded)


      .. bro:enum:: LoadedScripts::LOG Log::ID

         (present if :doc:`/scripts/policy/misc/loaded-scripts.bro` is loaded)


      .. bro:enum:: Stats::LOG Log::ID

         (present if :doc:`/scripts/policy/misc/stats.bro` is loaded)


      .. bro:enum:: WeirdStats::LOG Log::ID

         (present if :doc:`/scripts/policy/misc/weird-stats.bro` is loaded)


      .. bro:enum:: Known::HOSTS_LOG Log::ID

         (present if :doc:`/scripts/policy/protocols/conn/known-hosts.bro` is loaded)


      .. bro:enum:: Known::SERVICES_LOG Log::ID

         (present if :doc:`/scripts/policy/protocols/conn/known-services.bro` is loaded)


      .. bro:enum:: Known::MODBUS_LOG Log::ID

         (present if :doc:`/scripts/policy/protocols/modbus/known-masters-slaves.bro` is loaded)


      .. bro:enum:: Modbus::REGISTER_CHANGE_LOG Log::ID

         (present if :doc:`/scripts/policy/protocols/modbus/track-memmap.bro` is loaded)


      .. bro:enum:: SMB::CMD_LOG Log::ID

         (present if :doc:`/scripts/policy/protocols/smb/log-cmds.bro` is loaded)


      .. bro:enum:: Known::CERTS_LOG Log::ID

         (present if :doc:`/scripts/policy/protocols/ssl/known-certs.bro` is loaded)


      .. bro:enum:: BroxygenExample::LOG Log::ID

         (present if :doc:`/scripts/broxygen/example.bro` is loaded)


   Type that defines an ID unique to each log stream. Scripts creating new
   log streams need to redef this enum to add their own specific log ID.
   The log ID implicitly determines the default name of the generated log
   file.

.. bro:type:: Log::RotationInfo

   :Type: :bro:type:`record`

      writer: :bro:type:`Log::Writer`
         The log writer being used.

      fname: :bro:type:`string`
         Full name of the rotated file.

      path: :bro:type:`string`
         Original path value.

      open: :bro:type:`time`
         Time when opened.

      close: :bro:type:`time`
         Time when closed.

      terminating: :bro:type:`bool`
         True if rotation occured due to Bro shutting down.

   Information passed into rotation callback functions.

.. bro:type:: Log::Stream

   :Type: :bro:type:`record`

      columns: :bro:type:`any`
         A record type defining the log's columns.

      ev: :bro:type:`any` :bro:attr:`&optional`
         Event that will be raised once for each log entry.
         The event receives a single same parameter, an instance of
         type ``columns``.

      path: :bro:type:`string` :bro:attr:`&optional`
         A path that will be inherited by any filters added to the
         stream which do not already specify their own path.

   Type defining the content of a logging stream.

.. bro:type:: Log::Writer

   :Type: :bro:type:`enum`

      .. bro:enum:: Log::WRITER_ASCII Log::Writer

      .. bro:enum:: Log::WRITER_NONE Log::Writer

      .. bro:enum:: Log::WRITER_SQLITE Log::Writer


Functions
#########
.. bro:id:: Log::add_default_filter

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`) : :bro:type:`bool`

   Adds a default :bro:type:`Log::Filter` record with ``name`` field
   set as "default" to a given logging stream.
   

   :id: The ID associated with a logging stream for which to add a default
       filter.
   

   :returns: The status of a call to :bro:id:`Log::add_filter` using a
            default :bro:type:`Log::Filter` argument with ``name`` field
            set to "default".
   
   .. bro:see:: Log::add_filter Log::remove_filter
      Log::remove_default_filter

.. bro:id:: Log::add_filter

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`, filter: :bro:type:`Log::Filter`) : :bro:type:`bool`

   Adds a custom filter to an existing logging stream.  If a filter
   with a matching ``name`` field already exists for the stream, it
   is removed when the new filter is successfully added.
   

   :id: The ID associated with the logging stream to filter.
   

   :filter: A record describing the desired logging parameters.
   

   :returns: True if the filter was successfully added, false if
            the filter was not added or the *filter* argument was not
            the correct type.
   
   .. bro:see:: Log::remove_filter Log::add_default_filter
      Log::remove_default_filter Log::get_filter Log::get_filter_names

.. bro:id:: Log::create_stream

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`, stream: :bro:type:`Log::Stream`) : :bro:type:`bool`

   Creates a new logging stream with the default filter.
   

   :id: The ID enum to be associated with the new logging stream.
   

   :stream: A record defining the content that the new stream will log.
   

   :returns: True if a new logging stream was successfully created and
            a default filter added to it.
   
   .. bro:see:: Log::add_default_filter Log::remove_default_filter

.. bro:id:: Log::default_ext_func

   :Type: :bro:type:`function` (path: :bro:type:`string`) : :bro:type:`any`
   :Attributes: :bro:attr:`&redef`

   Default log extension function in the case that you would like to
   apply the same extensions to all logs.  The function *must* return
   a record with all of the fields to be included in the log. The
   default function included here does not return a value, which indicates
   that no extensions are added.

.. bro:id:: Log::default_path_func

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`, path: :bro:type:`string`, rec: :bro:type:`any`) : :bro:type:`string`
   :Attributes: :bro:attr:`&redef`

   Builds the default path values for log filters if not otherwise
   specified by a filter. The default implementation uses *id*
   to derive a name.  Upon adding a filter to a stream, if neither
   ``path`` nor ``path_func`` is explicitly set by them, then
   this function is used as the ``path_func``.
   

   :id: The ID associated with the log stream.
   

   :path: A suggested path value, which may be either the filter's
         ``path`` if defined, else a previous result from the function.
         If no ``path`` is defined for the filter, then the first call
         to the function will contain an empty string.
   

   :rec: An instance of the stream's ``columns`` type with its
        fields set to the values to be logged.
   

   :returns: The path to be used for the filter.

.. bro:id:: Log::disable_stream

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`) : :bro:type:`bool`

   Disables a currently enabled logging stream.  Disabled streams
   will not be written to until they are enabled again.  New streams
   are enabled by default.
   

   :id: The ID associated with the logging stream to disable.
   

   :returns: True if the stream is now disabled or was already disabled.
   
   .. bro:see:: Log::enable_stream

.. bro:id:: Log::enable_stream

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`) : :bro:type:`bool`

   Enables a previously disabled logging stream.  Disabled streams
   will not be written to until they are enabled again.  New streams
   are enabled by default.
   

   :id: The ID associated with the logging stream to enable.
   

   :returns: True if the stream is re-enabled or was not previously disabled.
   
   .. bro:see:: Log::disable_stream

.. bro:id:: Log::flush

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`) : :bro:type:`bool`

   Flushes any currently buffered output for all the writers of a given
   logging stream.
   

   :id: The ID associated with a logging stream for which to flush buffered
       data.
   

   :returns: True if all writers of a log stream were signalled to flush
            buffered data or if the logging stream is disabled,
            false if the logging stream does not exist.
   
   .. bro:see:: Log::set_buf Log::enable_stream Log::disable_stream

.. bro:id:: Log::get_filter

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`, name: :bro:type:`string`) : :bro:type:`Log::Filter`

   Gets a filter associated with an existing logging stream.
   

   :id: The ID associated with a logging stream from which to
       obtain one of its filters.
   

   :name: A string to match against the ``name`` field of a
         :bro:type:`Log::Filter` for identification purposes.
   

   :returns: A filter attached to the logging stream *id* matching
            *name* or, if no matches are found returns the
            :bro:id:`Log::no_filter` sentinel value.
   
   .. bro:see:: Log::add_filter Log::remove_filter Log::add_default_filter
                Log::remove_default_filter Log::get_filter_names

.. bro:id:: Log::get_filter_names

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`) : :bro:type:`set` [:bro:type:`string`]

   Gets the names of all filters associated with an existing
   logging stream.
   

   :id: The ID of a logging stream from which to obtain the list
       of filter names.
   

   :returns: The set of filter names associated with the stream.
   
   ..bro:see:: Log::remove_filter Log::add_default_filter
     Log::remove_default_filter Log::get_filter

.. bro:id:: Log::remove_default_filter

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`) : :bro:type:`bool`

   Removes the :bro:type:`Log::Filter` with ``name`` field equal to
   "default".
   

   :id: The ID associated with a logging stream from which to remove the
       default filter.
   

   :returns: The status of a call to :bro:id:`Log::remove_filter` using
            "default" as the argument.
   
   .. bro:see:: Log::add_filter Log::remove_filter Log::add_default_filter

.. bro:id:: Log::remove_filter

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`, name: :bro:type:`string`) : :bro:type:`bool`

   Removes a filter from an existing logging stream.
   

   :id: The ID associated with the logging stream from which to
       remove a filter.
   

   :name: A string to match against the ``name`` field of a
         :bro:type:`Log::Filter` for identification purposes.
   

   :returns: True if the logging stream's filter was removed or
            if no filter associated with *name* was found.
   
   .. bro:see:: Log::remove_filter Log::add_default_filter
      Log::remove_default_filter Log::get_filter Log::get_filter_names

.. bro:id:: Log::remove_stream

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`) : :bro:type:`bool`

   Removes a logging stream completely, stopping all the threads.
   

   :id: The ID associated with the logging stream.
   

   :returns: True if the stream was successfully removed.
   
   .. bro:see:: Log::create_stream

.. bro:id:: Log::run_rotation_postprocessor_cmd

   :Type: :bro:type:`function` (info: :bro:type:`Log::RotationInfo`, npath: :bro:type:`string`) : :bro:type:`bool`

   Runs a command given by :bro:id:`Log::default_rotation_postprocessor_cmd`
   on a rotated file.  Meant to be called from postprocessor functions
   that are added to :bro:id:`Log::default_rotation_postprocessors`.
   

   :info: A record holding meta-information about the log being rotated.
   

   :npath: The new path of the file (after already being rotated/processed
          by writer-specific postprocessor as defined in
          :bro:id:`Log::default_rotation_postprocessors`).
   

   :returns: True when :bro:id:`Log::default_rotation_postprocessor_cmd`
            is empty or the system command given by it has been invoked
            to postprocess a rotated log file.
   
   .. bro:see:: Log::default_rotation_date_format
      Log::default_rotation_postprocessor_cmd
      Log::default_rotation_postprocessors

.. bro:id:: Log::set_buf

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`, buffered: :bro:type:`bool`) : :bro:type:`bool`

   Sets the buffering status for all the writers of a given logging stream.
   A given writer implementation may or may not support buffering and if
   it doesn't then toggling buffering with this function has no effect.
   

   :id: The ID associated with a logging stream for which to
       enable/disable buffering.
   

   :buffered: Whether to enable or disable log buffering.
   

   :returns: True if buffering status was set, false if the logging stream
            does not exist.
   
   .. bro:see:: Log::flush

.. bro:id:: Log::write

   :Type: :bro:type:`function` (id: :bro:type:`Log::ID`, columns: :bro:type:`any`) : :bro:type:`bool`

   Writes a new log line/entry to a logging stream.
   

   :id: The ID associated with a logging stream to be written to.
   

   :columns: A record value describing the values of each field/column
            to write to the log stream.
   

   :returns: True if the stream was found and no error occurred in writing
            to it or if the stream was disabled and nothing was written.
            False if the stream was not found, or the *columns*
            argument did not match what the stream was initially defined
            to handle, or one of the stream's filters has an invalid
            ``path_func``.
   
   .. bro:see:: Log::enable_stream Log::disable_stream


