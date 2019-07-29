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
Redefinable Options
###################
=========================================================================================== =====================================================================
:zeek:id:`Log::default_ext_prefix`: :zeek:type:`string` :zeek:attr:`&redef`                 A prefix for extension fields which can be optionally prefixed
                                                                                            on all log lines by setting the `ext_func` field in the
                                                                                            log filter.
:zeek:id:`Log::default_field_name_map`: :zeek:type:`table` :zeek:attr:`&redef`              Default field name mapping for renaming fields in a logging framework
                                                                                            filter.
:zeek:id:`Log::default_mail_alarms_interval`: :zeek:type:`interval` :zeek:attr:`&redef`     Default alarm summary mail interval.
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
=================================================== =========================================================
:zeek:type:`Log::Filter`: :zeek:type:`record`       A filter type describes how to customize logging streams.
:zeek:type:`Log::ID`: :zeek:type:`enum`             Type that defines an ID unique to each log stream.
:zeek:type:`Log::RotationInfo`: :zeek:type:`record` Information passed into rotation callback functions.
:zeek:type:`Log::Stream`: :zeek:type:`record`       Type defining the content of a logging stream.
:zeek:type:`Log::Writer`: :zeek:type:`enum`         
=================================================== =========================================================

Functions
#########
============================================================================ ==========================================================================
:zeek:id:`Log::add_default_filter`: :zeek:type:`function`                    Adds a default :zeek:type:`Log::Filter` record with ``name`` field
                                                                             set as "default" to a given logging stream.
:zeek:id:`Log::add_filter`: :zeek:type:`function`                            Adds a custom filter to an existing logging stream.
:zeek:id:`Log::create_stream`: :zeek:type:`function`                         Creates a new logging stream with the default filter.
:zeek:id:`Log::default_ext_func`: :zeek:type:`function` :zeek:attr:`&redef`  Default log extension function in the case that you would like to
                                                                             apply the same extensions to all logs.
:zeek:id:`Log::default_path_func`: :zeek:type:`function` :zeek:attr:`&redef` Builds the default path values for log filters if not otherwise
                                                                             specified by a filter.
:zeek:id:`Log::disable_stream`: :zeek:type:`function`                        Disables a currently enabled logging stream.
:zeek:id:`Log::enable_stream`: :zeek:type:`function`                         Enables a previously disabled logging stream.
:zeek:id:`Log::flush`: :zeek:type:`function`                                 Flushes any currently buffered output for all the writers of a given
                                                                             logging stream.
:zeek:id:`Log::get_filter`: :zeek:type:`function`                            Gets a filter associated with an existing logging stream.
:zeek:id:`Log::get_filter_names`: :zeek:type:`function`                      Gets the names of all filters associated with an existing
                                                                             logging stream.
:zeek:id:`Log::remove_default_filter`: :zeek:type:`function`                 Removes the :zeek:type:`Log::Filter` with ``name`` field equal to
                                                                             "default".
:zeek:id:`Log::remove_filter`: :zeek:type:`function`                         Removes a filter from an existing logging stream.
:zeek:id:`Log::remove_stream`: :zeek:type:`function`                         Removes a logging stream completely, stopping all the threads.
:zeek:id:`Log::run_rotation_postprocessor_cmd`: :zeek:type:`function`        Runs a command given by :zeek:id:`Log::default_rotation_postprocessor_cmd`
                                                                             on a rotated file.
:zeek:id:`Log::set_buf`: :zeek:type:`function`                               Sets the buffering status for all the writers of a given logging stream.
:zeek:id:`Log::write`: :zeek:type:`function`                                 Writes a new log line/entry to a logging stream.
============================================================================ ==========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Log::default_ext_prefix

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"_"``

   A prefix for extension fields which can be optionally prefixed
   on all log lines by setting the `ext_func` field in the
   log filter.

.. zeek:id:: Log::default_field_name_map

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Default field name mapping for renaming fields in a logging framework
   filter.  This is typically used to ease integration with external
   data storage and analysis systems.

.. zeek:id:: Log::default_mail_alarms_interval

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0 secs``

   Default alarm summary mail interval. Zero disables alarm summary
   mails.
   
   Note that this is overridden by the ZeekControl MailAlarmsInterval
   option.

.. zeek:id:: Log::default_rotation_date_format

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"%Y-%m-%d-%H-%M-%S"``

   Default naming format for timestamps embedded into filenames.
   Uses a ``strftime()`` style.

.. zeek:id:: Log::default_rotation_interval

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0 secs``

   Default rotation interval to use for filters that do not specify
   an interval. Zero disables rotation.
   
   Note that this is overridden by the ZeekControl LogRotationInterval
   option.

.. zeek:id:: Log::default_rotation_postprocessor_cmd

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Default shell command to run on rotated files. Empty for none.

.. zeek:id:: Log::default_rotation_postprocessors

   :Type: :zeek:type:`table` [:zeek:type:`Log::Writer`] of :zeek:type:`function` (info: :zeek:type:`Log::RotationInfo`) : :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/frameworks/logging/writers/ascii.zeek`

      ``+=``::

         Log::WRITER_ASCII = LogAscii::default_rotation_postprocessor_func

   :Redefinition: from :doc:`/scripts/base/frameworks/logging/writers/none.zeek`

      ``+=``::

         Log::WRITER_NONE = LogNone::default_rotation_postprocessor_func


   Specifies the default postprocessor function per writer type.
   Entries in this table are initialized by each writer type.

.. zeek:id:: Log::default_scope_sep

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"."``

   Default separator for log field scopes when logs are unrolled and
   flattened.  This will be the string between field name components.
   For example, setting this to "_" will cause the typical field
   "id.orig_h" to turn into "id_orig_h".

.. zeek:id:: Log::default_writer

   :Type: :zeek:type:`Log::Writer`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``Log::WRITER_ASCII``

   Default writer to use if a filter does not specify anything else.

.. zeek:id:: Log::empty_field

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"(empty)"``

   Default string to use for empty fields. This should be different
   from *unset_field* to make the output unambiguous.
   Individual writers can use a different value.

.. zeek:id:: Log::enable_local_logging

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   If true, local logging is by default enabled for all filters.

.. zeek:id:: Log::enable_remote_logging

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   If true, remote logging is by default enabled for all filters.

.. zeek:id:: Log::separator

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"\x09"``

   Default separator to use between fields.
   Individual writers can use a different value.

.. zeek:id:: Log::set_separator

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``","``

   Default separator to use between elements of a set.
   Individual writers can use a different value.

.. zeek:id:: Log::unset_field

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"-"``

   Default string to use for an unset &optional field.
   Individual writers can use a different value.

Constants
#########
.. zeek:id:: Log::no_filter

   :Type: :zeek:type:`Log::Filter`
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
            ext_func=lambda_<1052917868251127101>
            ;
            interv=0 secs
            postprocessor=<uninitialized>
            config={

            }
         }


   Sentinel value for indicating that a filter was not found when looked up.

State Variables
###############
.. zeek:id:: Log::active_streams

   :Type: :zeek:type:`table` [:zeek:type:`Log::ID`] of :zeek:type:`Log::Stream`
   :Default: ``{}``

   The streams which are currently active and not disabled.
   This table is not meant to be modified by users!  Only use it for
   examining which streams are active.

Types
#####
.. zeek:type:: Log::Filter

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`
         Descriptive name to reference this filter.

      writer: :zeek:type:`Log::Writer` :zeek:attr:`&default` = :zeek:see:`Log::default_writer` :zeek:attr:`&optional`
         The logging writer implementation to use.

      pred: :zeek:type:`function` (rec: :zeek:type:`any`) : :zeek:type:`bool` :zeek:attr:`&optional`
         Indicates whether a log entry should be recorded.
         If not given, all entries are recorded.
         

         :rec: An instance of the stream's ``columns`` type with its
              fields set to the values to be logged.
         

         :returns: True if the entry is to be recorded.

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

   A filter type describes how to customize logging streams.

.. zeek:type:: Log::ID

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Log::UNKNOWN Log::ID

         Dummy place-holder.

      .. zeek:enum:: Broker::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/broker/log.zeek` is loaded)


      .. zeek:enum:: Files::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/files/main.zeek` is loaded)


         Logging stream for file analysis.

      .. zeek:enum:: Reporter::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/reporter/main.zeek` is loaded)


      .. zeek:enum:: Cluster::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/cluster/main.zeek` is loaded)


      .. zeek:enum:: Notice::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/notice/main.zeek` is loaded)


         This is the primary logging stream for notices.

      .. zeek:enum:: Notice::ALARM_LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/notice/main.zeek` is loaded)


         This is the alarm stream.

      .. zeek:enum:: Weird::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/notice/weird.zeek` is loaded)


      .. zeek:enum:: DPD::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/dpd/main.zeek` is loaded)


      .. zeek:enum:: Signatures::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/signatures/main.zeek` is loaded)


      .. zeek:enum:: PacketFilter::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/packet-filter/main.zeek` is loaded)


      .. zeek:enum:: Software::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/software/main.zeek` is loaded)


      .. zeek:enum:: Intel::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/intel/main.zeek` is loaded)


      .. zeek:enum:: Config::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/config/main.zeek` is loaded)


      .. zeek:enum:: Tunnel::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/tunnels/main.zeek` is loaded)


      .. zeek:enum:: OpenFlow::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/openflow/plugins/log.zeek` is loaded)


      .. zeek:enum:: NetControl::LOG Log::ID

         (present if :doc:`/scripts/base/frameworks/netcontrol/main.zeek` is loaded)


      .. zeek:enum:: NetControl::DROP Log::ID

         (present if :doc:`/scripts/base/frameworks/netcontrol/types.zeek` is loaded)


         Stop forwarding all packets matching the entity.
         
         No additional arguments.

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


      .. zeek:enum:: HTTP::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/http/main.zeek` is loaded)


      .. zeek:enum:: IRC::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/irc/main.zeek` is loaded)


      .. zeek:enum:: KRB::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/krb/main.zeek` is loaded)


      .. zeek:enum:: Modbus::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/modbus/main.zeek` is loaded)


      .. zeek:enum:: mysql::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/mysql/main.zeek` is loaded)


      .. zeek:enum:: NTLM::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/ntlm/main.zeek` is loaded)


      .. zeek:enum:: NTP::LOG Log::ID

         (present if :doc:`/scripts/base/protocols/ntp/main.zeek` is loaded)


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


      .. zeek:enum:: SMB::AUTH_LOG Log::ID

         (present if :doc:`/scripts/base/protocols/smb/main.zeek` is loaded)


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


      .. zeek:enum:: PE::LOG Log::ID

         (present if :doc:`/scripts/base/files/pe/main.zeek` is loaded)


      .. zeek:enum:: NetControl::CATCH_RELEASE Log::ID

         (present if :doc:`/scripts/policy/frameworks/netcontrol/catch-and-release.zeek` is loaded)


      .. zeek:enum:: Unified2::LOG Log::ID

         (present if :doc:`/scripts/policy/files/unified2/main.zeek` is loaded)


      .. zeek:enum:: OCSP::LOG Log::ID

         (present if :doc:`/scripts/policy/files/x509/log-ocsp.zeek` is loaded)


      .. zeek:enum:: Barnyard2::LOG Log::ID

         (present if :doc:`/scripts/policy/integration/barnyard2/main.zeek` is loaded)


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

.. zeek:type:: Log::RotationInfo

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
         True if rotation occured due to Zeek shutting down.

   Information passed into rotation callback functions.

.. zeek:type:: Log::Stream

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

   Type defining the content of a logging stream.

.. zeek:type:: Log::Writer

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Log::WRITER_ASCII Log::Writer

      .. zeek:enum:: Log::WRITER_NONE Log::Writer

      .. zeek:enum:: Log::WRITER_SQLITE Log::Writer


Functions
#########
.. zeek:id:: Log::add_default_filter

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`

   Adds a default :zeek:type:`Log::Filter` record with ``name`` field
   set as "default" to a given logging stream.
   

   :id: The ID associated with a logging stream for which to add a default
       filter.
   

   :returns: The status of a call to :zeek:id:`Log::add_filter` using a
            default :zeek:type:`Log::Filter` argument with ``name`` field
            set to "default".
   
   .. zeek:see:: Log::add_filter Log::remove_filter
      Log::remove_default_filter

.. zeek:id:: Log::add_filter

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, filter: :zeek:type:`Log::Filter`) : :zeek:type:`bool`

   Adds a custom filter to an existing logging stream.  If a filter
   with a matching ``name`` field already exists for the stream, it
   is removed when the new filter is successfully added.
   

   :id: The ID associated with the logging stream to filter.
   

   :filter: A record describing the desired logging parameters.
   

   :returns: True if the filter was successfully added, false if
            the filter was not added or the *filter* argument was not
            the correct type.
   
   .. zeek:see:: Log::remove_filter Log::add_default_filter
      Log::remove_default_filter Log::get_filter Log::get_filter_names

.. zeek:id:: Log::create_stream

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, stream: :zeek:type:`Log::Stream`) : :zeek:type:`bool`

   Creates a new logging stream with the default filter.
   

   :id: The ID enum to be associated with the new logging stream.
   

   :stream: A record defining the content that the new stream will log.
   

   :returns: True if a new logging stream was successfully created and
            a default filter added to it.
   
   .. zeek:see:: Log::add_default_filter Log::remove_default_filter

.. zeek:id:: Log::default_ext_func

   :Type: :zeek:type:`function` (path: :zeek:type:`string`) : :zeek:type:`any`
   :Attributes: :zeek:attr:`&redef`

   Default log extension function in the case that you would like to
   apply the same extensions to all logs.  The function *must* return
   a record with all of the fields to be included in the log. The
   default function included here does not return a value, which indicates
   that no extensions are added.

.. zeek:id:: Log::default_path_func

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, path: :zeek:type:`string`, rec: :zeek:type:`any`) : :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`

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

.. zeek:id:: Log::disable_stream

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`

   Disables a currently enabled logging stream.  Disabled streams
   will not be written to until they are enabled again.  New streams
   are enabled by default.
   

   :id: The ID associated with the logging stream to disable.
   

   :returns: True if the stream is now disabled or was already disabled.
   
   .. zeek:see:: Log::enable_stream

.. zeek:id:: Log::enable_stream

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`

   Enables a previously disabled logging stream.  Disabled streams
   will not be written to until they are enabled again.  New streams
   are enabled by default.
   

   :id: The ID associated with the logging stream to enable.
   

   :returns: True if the stream is re-enabled or was not previously disabled.
   
   .. zeek:see:: Log::disable_stream

.. zeek:id:: Log::flush

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`

   Flushes any currently buffered output for all the writers of a given
   logging stream.
   

   :id: The ID associated with a logging stream for which to flush buffered
       data.
   

   :returns: True if all writers of a log stream were signalled to flush
            buffered data or if the logging stream is disabled,
            false if the logging stream does not exist.
   
   .. zeek:see:: Log::set_buf Log::enable_stream Log::disable_stream

.. zeek:id:: Log::get_filter

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, name: :zeek:type:`string`) : :zeek:type:`Log::Filter`

   Gets a filter associated with an existing logging stream.
   

   :id: The ID associated with a logging stream from which to
       obtain one of its filters.
   

   :name: A string to match against the ``name`` field of a
         :zeek:type:`Log::Filter` for identification purposes.
   

   :returns: A filter attached to the logging stream *id* matching
            *name* or, if no matches are found returns the
            :zeek:id:`Log::no_filter` sentinel value.
   
   .. zeek:see:: Log::add_filter Log::remove_filter Log::add_default_filter
                Log::remove_default_filter Log::get_filter_names

.. zeek:id:: Log::get_filter_names

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`set` [:zeek:type:`string`]

   Gets the names of all filters associated with an existing
   logging stream.
   

   :id: The ID of a logging stream from which to obtain the list
       of filter names.
   

   :returns: The set of filter names associated with the stream.
   
   ..zeek:see:: Log::remove_filter Log::add_default_filter
     Log::remove_default_filter Log::get_filter

.. zeek:id:: Log::remove_default_filter

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`

   Removes the :zeek:type:`Log::Filter` with ``name`` field equal to
   "default".
   

   :id: The ID associated with a logging stream from which to remove the
       default filter.
   

   :returns: The status of a call to :zeek:id:`Log::remove_filter` using
            "default" as the argument.
   
   .. zeek:see:: Log::add_filter Log::remove_filter Log::add_default_filter

.. zeek:id:: Log::remove_filter

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, name: :zeek:type:`string`) : :zeek:type:`bool`

   Removes a filter from an existing logging stream.
   

   :id: The ID associated with the logging stream from which to
       remove a filter.
   

   :name: A string to match against the ``name`` field of a
         :zeek:type:`Log::Filter` for identification purposes.
   

   :returns: True if the logging stream's filter was removed or
            if no filter associated with *name* was found.
   
   .. zeek:see:: Log::remove_filter Log::add_default_filter
      Log::remove_default_filter Log::get_filter Log::get_filter_names

.. zeek:id:: Log::remove_stream

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`) : :zeek:type:`bool`

   Removes a logging stream completely, stopping all the threads.
   

   :id: The ID associated with the logging stream.
   

   :returns: True if the stream was successfully removed.
   
   .. zeek:see:: Log::create_stream

.. zeek:id:: Log::run_rotation_postprocessor_cmd

   :Type: :zeek:type:`function` (info: :zeek:type:`Log::RotationInfo`, npath: :zeek:type:`string`) : :zeek:type:`bool`

   Runs a command given by :zeek:id:`Log::default_rotation_postprocessor_cmd`
   on a rotated file.  Meant to be called from postprocessor functions
   that are added to :zeek:id:`Log::default_rotation_postprocessors`.
   

   :info: A record holding meta-information about the log being rotated.
   

   :npath: The new path of the file (after already being rotated/processed
          by writer-specific postprocessor as defined in
          :zeek:id:`Log::default_rotation_postprocessors`).
   

   :returns: True when :zeek:id:`Log::default_rotation_postprocessor_cmd`
            is empty or the system command given by it has been invoked
            to postprocess a rotated log file.
   
   .. zeek:see:: Log::default_rotation_date_format
      Log::default_rotation_postprocessor_cmd
      Log::default_rotation_postprocessors

.. zeek:id:: Log::set_buf

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, buffered: :zeek:type:`bool`) : :zeek:type:`bool`

   Sets the buffering status for all the writers of a given logging stream.
   A given writer implementation may or may not support buffering and if
   it doesn't then toggling buffering with this function has no effect.
   

   :id: The ID associated with a logging stream for which to
       enable/disable buffering.
   

   :buffered: Whether to enable or disable log buffering.
   

   :returns: True if buffering status was set, false if the logging stream
            does not exist.
   
   .. zeek:see:: Log::flush

.. zeek:id:: Log::write

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, columns: :zeek:type:`any`) : :zeek:type:`bool`

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
   
   .. zeek:see:: Log::enable_stream Log::disable_stream


