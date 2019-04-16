:tocdepth: 3

base/frameworks/notice/main.zeek
================================
.. bro:namespace:: GLOBAL
.. bro:namespace:: Notice

This is the notice framework which enables Bro to "notice" things which
are odd or potentially bad.  Decisions of the meaning of various notices
need to be done per site because Bro does not ship with assumptions about
what is bad activity for sites.  More extensive documentation about using
the notice framework can be found in :doc:`/frameworks/notice`.

:Namespaces: GLOBAL, Notice
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================================= =====================================================================
:bro:id:`Notice::alarmed_types`: :bro:type:`set` :bro:attr:`&redef`                     Alarmed notice types.
:bro:id:`Notice::default_suppression_interval`: :bro:type:`interval` :bro:attr:`&redef` The notice framework is able to do automatic notice suppression by
                                                                                        utilizing the *identifier* field in :bro:type:`Notice::Info` records.
:bro:id:`Notice::emailed_types`: :bro:type:`set` :bro:attr:`&redef`                     Emailed notice types.
:bro:id:`Notice::ignored_types`: :bro:type:`set` :bro:attr:`&redef`                     Ignored notice types.
:bro:id:`Notice::mail_from`: :bro:type:`string` :bro:attr:`&redef`                      Address that emails will be from.
:bro:id:`Notice::mail_subject_prefix`: :bro:type:`string` :bro:attr:`&redef`            Text string prefixed to the subject of all emails sent out.
:bro:id:`Notice::not_suppressed_types`: :bro:type:`set` :bro:attr:`&redef`              Types that should be suppressed for the default suppression interval.
:bro:id:`Notice::reply_to`: :bro:type:`string` :bro:attr:`&redef`                       Reply-to address used in outbound email.
:bro:id:`Notice::sendmail`: :bro:type:`string` :bro:attr:`&redef`                       Local system sendmail program.
======================================================================================= =====================================================================

Redefinable Options
###################
================================================================================== ====================================================================
:bro:id:`Notice::mail_dest`: :bro:type:`string` :bro:attr:`&redef`                 Email address to send notices with the
                                                                                   :bro:enum:`Notice::ACTION_EMAIL` action or to send bulk alarm logs
                                                                                   on rotation with :bro:enum:`Notice::ACTION_ALARM`.
:bro:id:`Notice::max_email_delay`: :bro:type:`interval` :bro:attr:`&redef`         The maximum amount of time a plugin can delay email from being sent.
:bro:id:`Notice::type_suppression_intervals`: :bro:type:`table` :bro:attr:`&redef` This table can be used as a shorthand way to modify suppression
                                                                                   intervals for entire notice types.
================================================================================== ====================================================================

Types
#####
================================================ =====================================================================
:bro:type:`Notice::Action`: :bro:type:`enum`     These are values representing actions that can be taken with notices.
:bro:type:`Notice::ActionSet`: :bro:type:`set`   Type that represents a set of actions.
:bro:type:`Notice::FileInfo`: :bro:type:`record` Contains a portion of :bro:see:`fa_file` that's also contained in
                                                 :bro:see:`Notice::Info`.
:bro:type:`Notice::Info`: :bro:type:`record`     The record type that is used for representing and logging notices.
:bro:type:`Notice::Type`: :bro:type:`enum`       Scripts creating new notices need to redef this enum to add their
                                                 own specific notice types which would then get used when they call
                                                 the :bro:id:`NOTICE` function.
================================================ =====================================================================

Redefinitions
#############
===================================== =
:bro:type:`Log::ID`: :bro:type:`enum` 
===================================== =

Events
######
====================================================== ================================================================
:bro:id:`Notice::begin_suppression`: :bro:type:`event` This event is generated when a notice begins to be suppressed.
:bro:id:`Notice::cluster_notice`: :bro:type:`event`    This is the event used to transport notices on the cluster.
:bro:id:`Notice::log_notice`: :bro:type:`event`        This event can be handled to access the :bro:type:`Notice::Info`
                                                       record as it is sent on to the logging framework.
:bro:id:`Notice::suppressed`: :bro:type:`event`        This event is generated on each occurrence of an event being
                                                       suppressed.
====================================================== ================================================================

Hooks
#####
========================================== ==========================================================
:bro:id:`Notice::notice`: :bro:type:`hook` This is the event that is called as the entry point to the
                                           notice framework by the global :bro:id:`NOTICE` function.
:bro:id:`Notice::policy`: :bro:type:`hook` The hook to modify notice handling.
========================================== ==========================================================

Functions
#########
================================================================= =========================================================================
:bro:id:`NOTICE`: :bro:type:`function`                            
:bro:id:`Notice::create_file_info`: :bro:type:`function`          Creates a record containing a subset of a full :bro:see:`fa_file` record.
:bro:id:`Notice::email_headers`: :bro:type:`function`             Constructs mail headers to which an email body can be appended for
                                                                  sending with sendmail.
:bro:id:`Notice::email_notice_to`: :bro:type:`function`           Call this function to send a notice in an email.
:bro:id:`Notice::internal_NOTICE`: :bro:type:`function`           This is an internal wrapper for the global :bro:id:`NOTICE`
                                                                  function; disregard.
:bro:id:`Notice::is_being_suppressed`: :bro:type:`function`       A function to determine if an event is supposed to be suppressed.
:bro:id:`Notice::log_mailing_postprocessor`: :bro:type:`function` A log postprocessing function that implements emailing the contents
                                                                  of a log upon rotation to any configured :bro:id:`Notice::mail_dest`.
:bro:id:`Notice::populate_file_info`: :bro:type:`function`        Populates file-related fields in a notice info record.
:bro:id:`Notice::populate_file_info2`: :bro:type:`function`       Populates file-related fields in a notice info record.
================================================================= =========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Notice::alarmed_types

   :Type: :bro:type:`set` [:bro:type:`Notice::Type`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Alarmed notice types.

.. bro:id:: Notice::default_suppression_interval

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1.0 hr``

   The notice framework is able to do automatic notice suppression by
   utilizing the *identifier* field in :bro:type:`Notice::Info` records.
   Set this to "0secs" to completely disable automated notice
   suppression.

.. bro:id:: Notice::emailed_types

   :Type: :bro:type:`set` [:bro:type:`Notice::Type`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Emailed notice types.

.. bro:id:: Notice::ignored_types

   :Type: :bro:type:`set` [:bro:type:`Notice::Type`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Ignored notice types.

.. bro:id:: Notice::mail_from

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"Big Brother <bro@localhost>"``

   Address that emails will be from.
   
   Note that this is overridden by the BroControl MailFrom option.

.. bro:id:: Notice::mail_subject_prefix

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"[Bro]"``

   Text string prefixed to the subject of all emails sent out.
   
   Note that this is overridden by the BroControl MailSubjectPrefix
   option.

.. bro:id:: Notice::not_suppressed_types

   :Type: :bro:type:`set` [:bro:type:`Notice::Type`]
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   Types that should be suppressed for the default suppression interval.

.. bro:id:: Notice::reply_to

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Reply-to address used in outbound email.

.. bro:id:: Notice::sendmail

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"/usr/sbin/sendmail"``

   Local system sendmail program.
   
   Note that this is overridden by the BroControl SendMail option.

Redefinable Options
###################
.. bro:id:: Notice::mail_dest

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Email address to send notices with the
   :bro:enum:`Notice::ACTION_EMAIL` action or to send bulk alarm logs
   on rotation with :bro:enum:`Notice::ACTION_ALARM`.
   
   Note that this is overridden by the BroControl MailTo option.

.. bro:id:: Notice::max_email_delay

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``15.0 secs``

   The maximum amount of time a plugin can delay email from being sent.

.. bro:id:: Notice::type_suppression_intervals

   :Type: :bro:type:`table` [:bro:type:`Notice::Type`] of :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``{}``

   This table can be used as a shorthand way to modify suppression
   intervals for entire notice types.

Types
#####
.. bro:type:: Notice::Action

   :Type: :bro:type:`enum`

      .. bro:enum:: Notice::ACTION_NONE Notice::Action

         Indicates that there is no action to be taken.

      .. bro:enum:: Notice::ACTION_LOG Notice::Action

         Indicates that the notice should be sent to the notice
         logging stream.

      .. bro:enum:: Notice::ACTION_EMAIL Notice::Action

         Indicates that the notice should be sent to the email
         address(es) configured in the :bro:id:`Notice::mail_dest`
         variable.

      .. bro:enum:: Notice::ACTION_ALARM Notice::Action

         Indicates that the notice should be alarmed.  A readable
         ASCII version of the alarm log is emailed in bulk to the
         address(es) configured in :bro:id:`Notice::mail_dest`.

      .. bro:enum:: Notice::ACTION_DROP Notice::Action

         (present if :doc:`/scripts/base/frameworks/notice/actions/drop.zeek` is loaded)


         Drops the address via :bro:see:`NetControl::drop_address_catch_release`.

      .. bro:enum:: Notice::ACTION_EMAIL_ADMIN Notice::Action

         (present if :doc:`/scripts/base/frameworks/notice/actions/email_admin.zeek` is loaded)


         Indicate that the generated email should be addressed to the 
         appropriate email addresses as found by the
         :bro:id:`Site::get_emails` function based on the relevant 
         address or addresses indicated in the notice.

      .. bro:enum:: Notice::ACTION_PAGE Notice::Action

         (present if :doc:`/scripts/base/frameworks/notice/actions/page.zeek` is loaded)


         Indicates that the notice should be sent to the pager email
         address configured in the :bro:id:`Notice::mail_page_dest`
         variable.

      .. bro:enum:: Notice::ACTION_ADD_GEODATA Notice::Action

         (present if :doc:`/scripts/base/frameworks/notice/actions/add-geodata.zeek` is loaded)


         Indicates that the notice should have geodata added for the
         "remote" host.  :bro:id:`Site::local_nets` must be defined
         in order for this to work.

   These are values representing actions that can be taken with notices.

.. bro:type:: Notice::ActionSet

   :Type: :bro:type:`set` [:bro:type:`Notice::Action`]

   Type that represents a set of actions.

.. bro:type:: Notice::FileInfo

   :Type: :bro:type:`record`

      fuid: :bro:type:`string`
         File UID.

      desc: :bro:type:`string`
         File description from e.g.
         :bro:see:`Files::describe`.

      mime: :bro:type:`string` :bro:attr:`&optional`
         Strongest mime type match for file.

      cid: :bro:type:`conn_id` :bro:attr:`&optional`
         Connection tuple over which file is sent.

      cuid: :bro:type:`string` :bro:attr:`&optional`
         Connection UID over which file is sent.

   Contains a portion of :bro:see:`fa_file` that's also contained in
   :bro:see:`Notice::Info`.

.. bro:type:: Notice::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log` :bro:attr:`&optional`
         An absolute time indicating when the notice occurred,
         defaults to the current network time.

      uid: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         A connection UID which uniquely identifies the endpoints
         concerned with the notice.

      id: :bro:type:`conn_id` :bro:attr:`&log` :bro:attr:`&optional`
         A connection 4-tuple identifying the endpoints concerned
         with the notice.

      conn: :bro:type:`connection` :bro:attr:`&optional`
         A shorthand way of giving the uid and id to a notice.  The
         reference to the actual connection will be deleted after
         applying the notice policy.

      iconn: :bro:type:`icmp_conn` :bro:attr:`&optional`
         A shorthand way of giving the uid and id to a notice.  The
         reference to the actual connection will be deleted after
         applying the notice policy.

      f: :bro:type:`fa_file` :bro:attr:`&optional`
         A file record if the notice is related to a file.  The
         reference to the actual fa_file record will be deleted after
         applying the notice policy.

      fuid: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         A file unique ID if this notice is related to a file.  If
         the *f* field is provided, this will be automatically filled
         out.

      file_mime_type: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         A mime type if the notice is related to a file.  If the *f*
         field is provided, this will be automatically filled out.

      file_desc: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Frequently files can be "described" to give a bit more
         context.  This field will typically be automatically filled
         out from an fa_file record.  For example, if a notice was
         related to a file over HTTP, the URL of the request would
         be shown.

      proto: :bro:type:`transport_proto` :bro:attr:`&log` :bro:attr:`&optional`
         The transport protocol. Filled automatically when either
         *conn*, *iconn* or *p* is specified.

      note: :bro:type:`Notice::Type` :bro:attr:`&log`
         The :bro:type:`Notice::Type` of the notice.

      msg: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The human readable message for the notice.

      sub: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The human readable sub-message.

      src: :bro:type:`addr` :bro:attr:`&log` :bro:attr:`&optional`
         Source address, if we don't have a :bro:type:`conn_id`.

      dst: :bro:type:`addr` :bro:attr:`&log` :bro:attr:`&optional`
         Destination address.

      p: :bro:type:`port` :bro:attr:`&log` :bro:attr:`&optional`
         Associated port, if we don't have a :bro:type:`conn_id`.

      n: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         Associated count, or perhaps a status code.

      peer_name: :bro:type:`string` :bro:attr:`&optional`
         Name of remote peer that raised this notice.

      peer_descr: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Textual description for the peer that raised this notice,
         including name, host address and port.

      actions: :bro:type:`Notice::ActionSet` :bro:attr:`&log` :bro:attr:`&default` = ``{  }`` :bro:attr:`&optional`
         The actions which have been applied to this notice.

      email_body_sections: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&optional`
         By adding chunks of text into this element, other scripts
         can expand on notices that are being emailed.  The normal
         way to add text is to extend the vector by handling the
         :bro:id:`Notice::notice` event and modifying the notice in
         place.

      email_delay_tokens: :bro:type:`set` [:bro:type:`string`] :bro:attr:`&optional`
         Adding a string "token" to this set will cause the notice
         framework's built-in emailing functionality to delay sending
         the email until either the token has been removed or the
         email has been delayed for :bro:id:`Notice::max_email_delay`.

      identifier: :bro:type:`string` :bro:attr:`&optional`
         This field is to be provided when a notice is generated for
         the purpose of deduplicating notices.  The identifier string
         should be unique for a single instance of the notice.  This
         field should be filled out in almost all cases when
         generating notices to define when a notice is conceptually
         a duplicate of a previous notice.
         
         For example, an SSL certificate that is going to expire soon
         should always have the same identifier no matter the client
         IP address that connected and resulted in the certificate
         being exposed.  In this case, the resp_h, resp_p, and hash
         of the certificate would be used to create this value.  The
         hash of the cert is included because servers can return
         multiple certificates on the same port.
         
         Another example might be a host downloading a file which
         triggered a notice because the MD5 sum of the file it
         downloaded was known by some set of intelligence.  In that
         case, the orig_h (client) and MD5 sum would be used in this
         field to dedup because if the same file is downloaded over
         and over again you really only want to know about it a
         single time.  This makes it possible to send those notices
         to email without worrying so much about sending thousands
         of emails.

      suppress_for: :bro:type:`interval` :bro:attr:`&log` :bro:attr:`&default` = :bro:see:`Notice::default_suppression_interval` :bro:attr:`&optional`
         This field indicates the length of time that this
         unique notice should be suppressed.

      dropped: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/notice/actions/drop.zeek` is loaded)

         Indicate if the $src IP address was dropped and denied
         network access.

      remote_location: :bro:type:`geo_location` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/notice/actions/add-geodata.zeek` is loaded)

         If GeoIP support is built in, notices can have geographic
         information attached to them.

   The record type that is used for representing and logging notices.

.. bro:type:: Notice::Type

   :Type: :bro:type:`enum`

      .. bro:enum:: Notice::Tally Notice::Type

         Notice reporting a count of how often a notice occurred.

      .. bro:enum:: Weird::Activity Notice::Type

         (present if :doc:`/scripts/base/frameworks/notice/weird.zeek` is loaded)


         Generic unusual but notice-worthy weird activity.

      .. bro:enum:: Signatures::Sensitive_Signature Notice::Type

         (present if :doc:`/scripts/base/frameworks/signatures/main.zeek` is loaded)


         Generic notice type for notice-worthy signature matches.

      .. bro:enum:: Signatures::Multiple_Signatures Notice::Type

         (present if :doc:`/scripts/base/frameworks/signatures/main.zeek` is loaded)


         Host has triggered many signatures on the same host.  The
         number of signatures is defined by the
         :bro:id:`Signatures::vert_scan_thresholds` variable.

      .. bro:enum:: Signatures::Multiple_Sig_Responders Notice::Type

         (present if :doc:`/scripts/base/frameworks/signatures/main.zeek` is loaded)


         Host has triggered the same signature on multiple hosts as
         defined by the :bro:id:`Signatures::horiz_scan_thresholds`
         variable.

      .. bro:enum:: Signatures::Count_Signature Notice::Type

         (present if :doc:`/scripts/base/frameworks/signatures/main.zeek` is loaded)


         The same signature has triggered multiple times for a host.
         The number of times the signature has been triggered is
         defined by the :bro:id:`Signatures::count_thresholds`
         variable. To generate this notice, the
         :bro:enum:`Signatures::SIG_COUNT_PER_RESP` action must be
         set for the signature.

      .. bro:enum:: Signatures::Signature_Summary Notice::Type

         (present if :doc:`/scripts/base/frameworks/signatures/main.zeek` is loaded)


         Summarize the number of times a host triggered a signature.
         The interval between summaries is defined by the
         :bro:id:`Signatures::summary_interval` variable.

      .. bro:enum:: PacketFilter::Compile_Failure Notice::Type

         (present if :doc:`/scripts/base/frameworks/packet-filter/main.zeek` is loaded)


         This notice is generated if a packet filter cannot be compiled.

      .. bro:enum:: PacketFilter::Install_Failure Notice::Type

         (present if :doc:`/scripts/base/frameworks/packet-filter/main.zeek` is loaded)


         Generated if a packet filter fails to install.

      .. bro:enum:: PacketFilter::Too_Long_To_Compile_Filter Notice::Type

         (present if :doc:`/scripts/base/frameworks/packet-filter/main.zeek` is loaded)


         Generated when a notice takes too long to compile.

      .. bro:enum:: PacketFilter::Dropped_Packets Notice::Type

         (present if :doc:`/scripts/base/frameworks/packet-filter/netstats.zeek` is loaded)


         Indicates packets were dropped by the packet filter.

      .. bro:enum:: ProtocolDetector::Protocol_Found Notice::Type

         (present if :doc:`/scripts/policy/frameworks/dpd/detect-protocols.zeek` is loaded)


      .. bro:enum:: ProtocolDetector::Server_Found Notice::Type

         (present if :doc:`/scripts/policy/frameworks/dpd/detect-protocols.zeek` is loaded)


      .. bro:enum:: Intel::Notice Notice::Type

         (present if :doc:`/scripts/policy/frameworks/intel/do_notice.zeek` is loaded)


         This notice is generated when an intelligence
         indicator is denoted to be notice-worthy.

      .. bro:enum:: TeamCymruMalwareHashRegistry::Match Notice::Type

         (present if :doc:`/scripts/policy/frameworks/files/detect-MHR.zeek` is loaded)


         The hash value of a file transferred over HTTP matched in the
         malware hash registry.

      .. bro:enum:: PacketFilter::No_More_Conn_Shunts_Available Notice::Type

         (present if :doc:`/scripts/policy/frameworks/packet-filter/shunt.zeek` is loaded)


         Indicative that :bro:id:`PacketFilter::max_bpf_shunts`
         connections are already being shunted with BPF filters and
         no more are allowed.

      .. bro:enum:: PacketFilter::Cannot_BPF_Shunt_Conn Notice::Type

         (present if :doc:`/scripts/policy/frameworks/packet-filter/shunt.zeek` is loaded)


         Limitations in BPF make shunting some connections with BPF
         impossible.  This notice encompasses those various cases.

      .. bro:enum:: Software::Software_Version_Change Notice::Type

         (present if :doc:`/scripts/policy/frameworks/software/version-changes.zeek` is loaded)


         For certain software, a version changing may matter.  In that
         case, this notice will be generated.  Software that matters
         if the version changes can be configured with the
         :bro:id:`Software::interesting_version_changes` variable.

      .. bro:enum:: Software::Vulnerable_Version Notice::Type

         (present if :doc:`/scripts/policy/frameworks/software/vulnerable.zeek` is loaded)


         Indicates that a vulnerable version of software was detected.

      .. bro:enum:: CaptureLoss::Too_Much_Loss Notice::Type

         (present if :doc:`/scripts/policy/misc/capture-loss.zeek` is loaded)


         Report if the detected capture loss exceeds the percentage
         threshold.

      .. bro:enum:: Traceroute::Detected Notice::Type

         (present if :doc:`/scripts/policy/misc/detect-traceroute/main.zeek` is loaded)


         Indicates that a host was seen running traceroutes.  For more
         detail about specific traceroutes that we run, refer to the
         traceroute.log.

      .. bro:enum:: Scan::Address_Scan Notice::Type

         (present if :doc:`/scripts/policy/misc/scan.zeek` is loaded)


         Address scans detect that a host appears to be scanning some
         number of destinations on a single port. This notice is
         generated when more than :bro:id:`Scan::addr_scan_threshold`
         unique hosts are seen over the previous
         :bro:id:`Scan::addr_scan_interval` time range.

      .. bro:enum:: Scan::Port_Scan Notice::Type

         (present if :doc:`/scripts/policy/misc/scan.zeek` is loaded)


         Port scans detect that an attacking host appears to be
         scanning a single victim host on several ports.  This notice
         is generated when an attacking host attempts to connect to
         :bro:id:`Scan::port_scan_threshold`
         unique ports on a single host over the previous
         :bro:id:`Scan::port_scan_interval` time range.

      .. bro:enum:: Conn::Retransmission_Inconsistency Notice::Type

         (present if :doc:`/scripts/policy/protocols/conn/weirds.zeek` is loaded)


         Possible evasion; usually just chud.

      .. bro:enum:: Conn::Content_Gap Notice::Type

         (present if :doc:`/scripts/policy/protocols/conn/weirds.zeek` is loaded)


         Data has sequence hole; perhaps due to filtering.

      .. bro:enum:: DNS::External_Name Notice::Type

         (present if :doc:`/scripts/policy/protocols/dns/detect-external-names.zeek` is loaded)


         Raised when a non-local name is found to be pointing at a
         local host.  The :bro:id:`Site::local_zones` variable
         **must** be set appropriately for this detection.

      .. bro:enum:: FTP::Bruteforcing Notice::Type

         (present if :doc:`/scripts/policy/protocols/ftp/detect-bruteforcing.zeek` is loaded)


         Indicates a host bruteforcing FTP logins by watching for too
         many rejected usernames or failed passwords.

      .. bro:enum:: FTP::Site_Exec_Success Notice::Type

         (present if :doc:`/scripts/policy/protocols/ftp/detect.zeek` is loaded)


         Indicates that a successful response to a "SITE EXEC" 
         command/arg pair was seen.

      .. bro:enum:: HTTP::SQL_Injection_Attacker Notice::Type

         (present if :doc:`/scripts/policy/protocols/http/detect-sqli.zeek` is loaded)


         Indicates that a host performing SQL injection attacks was
         detected.

      .. bro:enum:: HTTP::SQL_Injection_Victim Notice::Type

         (present if :doc:`/scripts/policy/protocols/http/detect-sqli.zeek` is loaded)


         Indicates that a host was seen to have SQL injection attacks
         against it.  This is tracked by IP address as opposed to
         hostname.

      .. bro:enum:: SMTP::Blocklist_Error_Message Notice::Type

         (present if :doc:`/scripts/policy/protocols/smtp/blocklists.zeek` is loaded)


         An SMTP server sent a reply mentioning an SMTP block list.

      .. bro:enum:: SMTP::Blocklist_Blocked_Host Notice::Type

         (present if :doc:`/scripts/policy/protocols/smtp/blocklists.zeek` is loaded)


         The originator's address is seen in the block list error message.
         This is useful to detect local hosts sending SPAM with a high
         positive rate.

      .. bro:enum:: SMTP::Suspicious_Origination Notice::Type

         (present if :doc:`/scripts/policy/protocols/smtp/detect-suspicious-orig.zeek` is loaded)


      .. bro:enum:: SSH::Password_Guessing Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssh/detect-bruteforcing.zeek` is loaded)


         Indicates that a host has been identified as crossing the
         :bro:id:`SSH::password_guesses_limit` threshold with
         failed logins.

      .. bro:enum:: SSH::Login_By_Password_Guesser Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssh/detect-bruteforcing.zeek` is loaded)


         Indicates that a host previously identified as a "password
         guesser" has now had a successful login
         attempt. This is not currently implemented.

      .. bro:enum:: SSH::Watched_Country_Login Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssh/geo-data.zeek` is loaded)


         If an SSH login is seen to or from a "watched" country based
         on the :bro:id:`SSH::watched_countries` variable then this
         notice will be generated.

      .. bro:enum:: SSH::Interesting_Hostname_Login Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssh/interesting-hostnames.zeek` is loaded)


         Generated if a login originates or responds with a host where
         the reverse hostname lookup resolves to a name matched by the
         :bro:id:`SSH::interesting_hostnames` regular expression.

      .. bro:enum:: SSL::Certificate_Expired Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/expiring-certs.zeek` is loaded)


         Indicates that a certificate's NotValidAfter date has lapsed
         and the certificate is now invalid.

      .. bro:enum:: SSL::Certificate_Expires_Soon Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/expiring-certs.zeek` is loaded)


         Indicates that a certificate is going to expire within 
         :bro:id:`SSL::notify_when_cert_expiring_in`.

      .. bro:enum:: SSL::Certificate_Not_Valid_Yet Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/expiring-certs.zeek` is loaded)


         Indicates that a certificate's NotValidBefore date is future
         dated.

      .. bro:enum:: Heartbleed::SSL_Heartbeat_Attack Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/heartbleed.zeek` is loaded)


         Indicates that a host performed a heartbleed attack or scan.

      .. bro:enum:: Heartbleed::SSL_Heartbeat_Attack_Success Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/heartbleed.zeek` is loaded)


         Indicates that a host performing a heartbleed attack was probably successful.

      .. bro:enum:: Heartbleed::SSL_Heartbeat_Odd_Length Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/heartbleed.zeek` is loaded)


         Indicates we saw heartbeat requests with odd length. Probably an attack or scan.

      .. bro:enum:: Heartbleed::SSL_Heartbeat_Many_Requests Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/heartbleed.zeek` is loaded)


         Indicates we saw many heartbeat requests without a reply. Might be an attack.

      .. bro:enum:: SSL::Invalid_Server_Cert Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/validate-certs.zeek` is loaded)


         This notice indicates that the result of validating the
         certificate along with its full certificate chain was
         invalid.

      .. bro:enum:: SSL::Invalid_Ocsp_Response Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/validate-ocsp.zeek` is loaded)


         This indicates that the OCSP response was not deemed
         to be valid.

      .. bro:enum:: SSL::Weak_Key Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/weak-keys.zeek` is loaded)


         Indicates that a server is using a potentially unsafe key.

      .. bro:enum:: SSL::Old_Version Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/weak-keys.zeek` is loaded)


         Indicates that a server is using a potentially unsafe version

      .. bro:enum:: SSL::Weak_Cipher Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/weak-keys.zeek` is loaded)


         Indicates that a server is using a potentially unsafe cipher

      .. bro:enum:: BroxygenExample::Broxygen_One Notice::Type

         (present if :doc:`/scripts/broxygen/example.zeek` is loaded)


         Any number of this type of comment
         will document "Broxygen_One".

      .. bro:enum:: BroxygenExample::Broxygen_Two Notice::Type

         (present if :doc:`/scripts/broxygen/example.zeek` is loaded)


         Any number of this type of comment
         will document "BROXYGEN_TWO".

      .. bro:enum:: BroxygenExample::Broxygen_Three Notice::Type

         (present if :doc:`/scripts/broxygen/example.zeek` is loaded)


      .. bro:enum:: BroxygenExample::Broxygen_Four Notice::Type

         (present if :doc:`/scripts/broxygen/example.zeek` is loaded)


         Omitting comments is fine, and so is mixing ``##`` and ``##<``, but
         it's probably best to use only one style consistently.

   Scripts creating new notices need to redef this enum to add their
   own specific notice types which would then get used when they call
   the :bro:id:`NOTICE` function.  The convention is to give a general
   category along with the specific notice separating words with
   underscores and using leading capitals on each word except for
   abbreviations which are kept in all capitals. For example,
   SSH::Password_Guessing is for hosts that have crossed a threshold of
   failed SSH logins.

Events
######
.. bro:id:: Notice::begin_suppression

   :Type: :bro:type:`event` (ts: :bro:type:`time`, suppress_for: :bro:type:`interval`, note: :bro:type:`Notice::Type`, identifier: :bro:type:`string`)

   This event is generated when a notice begins to be suppressed.
   

   :ts: time indicating then when the notice to be suppressed occured.
   

   :suppress_for: length of time that this notice should be suppressed.
   

   :note: The :bro:type:`Notice::Type` of the notice.
   

   :identifier: The identifier string of the notice that should be suppressed.

.. bro:id:: Notice::cluster_notice

   :Type: :bro:type:`event` (n: :bro:type:`Notice::Info`)

   This is the event used to transport notices on the cluster.
   

   :n: The notice information to be sent to the cluster manager for
      further processing.

.. bro:id:: Notice::log_notice

   :Type: :bro:type:`event` (rec: :bro:type:`Notice::Info`)

   This event can be handled to access the :bro:type:`Notice::Info`
   record as it is sent on to the logging framework.
   

   :rec: The record containing notice data before it is logged.

.. bro:id:: Notice::suppressed

   :Type: :bro:type:`event` (n: :bro:type:`Notice::Info`)

   This event is generated on each occurrence of an event being
   suppressed.
   

   :n: The record containing notice data regarding the notice type
      being suppressed.

Hooks
#####
.. bro:id:: Notice::notice

   :Type: :bro:type:`hook` (n: :bro:type:`Notice::Info`) : :bro:type:`bool`

   This is the event that is called as the entry point to the
   notice framework by the global :bro:id:`NOTICE` function.  By the
   time this event is generated, default values have already been
   filled out in the :bro:type:`Notice::Info` record and the notice
   policy has also been applied.
   

   :n: The record containing notice data.

.. bro:id:: Notice::policy

   :Type: :bro:type:`hook` (n: :bro:type:`Notice::Info`) : :bro:type:`bool`

   The hook to modify notice handling.

Functions
#########
.. bro:id:: NOTICE

   :Type: :bro:type:`function` (n: :bro:type:`Notice::Info`) : :bro:type:`void`


.. bro:id:: Notice::create_file_info

   :Type: :bro:type:`function` (f: :bro:type:`fa_file`) : :bro:type:`Notice::FileInfo`

   Creates a record containing a subset of a full :bro:see:`fa_file` record.
   

   :f: record containing metadata about a file.
   

   :returns: record containing a subset of fields copied from *f*.

.. bro:id:: Notice::email_headers

   :Type: :bro:type:`function` (subject_desc: :bro:type:`string`, dest: :bro:type:`string`) : :bro:type:`string`

   Constructs mail headers to which an email body can be appended for
   sending with sendmail.
   

   :subject_desc: a subject string to use for the mail.
   

   :dest: recipient string to use for the mail.
   

   :returns: a string of mail headers to which an email body can be
            appended.

.. bro:id:: Notice::email_notice_to

   :Type: :bro:type:`function` (n: :bro:type:`Notice::Info`, dest: :bro:type:`string`, extend: :bro:type:`bool`) : :bro:type:`void`

   Call this function to send a notice in an email.  It is already used
   by default with the built in :bro:enum:`Notice::ACTION_EMAIL` and
   :bro:enum:`Notice::ACTION_PAGE` actions.
   

   :n: The record of notice data to email.
   

   :dest: The intended recipient of the notice email.
   

   :extend: Whether to extend the email using the
           ``email_body_sections`` field of *n*.

.. bro:id:: Notice::internal_NOTICE

   :Type: :bro:type:`function` (n: :bro:type:`Notice::Info`) : :bro:type:`void`

   This is an internal wrapper for the global :bro:id:`NOTICE`
   function; disregard.
   

   :n: The record of notice data.

.. bro:id:: Notice::is_being_suppressed

   :Type: :bro:type:`function` (n: :bro:type:`Notice::Info`) : :bro:type:`bool`

   A function to determine if an event is supposed to be suppressed.
   

   :n: The record containing the notice in question.

.. bro:id:: Notice::log_mailing_postprocessor

   :Type: :bro:type:`function` (info: :bro:type:`Log::RotationInfo`) : :bro:type:`bool`

   A log postprocessing function that implements emailing the contents
   of a log upon rotation to any configured :bro:id:`Notice::mail_dest`.
   The rotated log is removed upon being sent.
   

   :info: A record containing the rotated log file information.
   

   :returns: True.

.. bro:id:: Notice::populate_file_info

   :Type: :bro:type:`function` (f: :bro:type:`fa_file`, n: :bro:type:`Notice::Info`) : :bro:type:`void`

   Populates file-related fields in a notice info record.
   

   :f: record containing metadata about a file.
   

   :n: a notice record that needs file-related fields populated.

.. bro:id:: Notice::populate_file_info2

   :Type: :bro:type:`function` (fi: :bro:type:`Notice::FileInfo`, n: :bro:type:`Notice::Info`) : :bro:type:`void`

   Populates file-related fields in a notice info record.
   

   :fi: record containing metadata about a file.
   

   :n: a notice record that needs file-related fields populated.


