:tocdepth: 3

base/frameworks/notice/main.zeek
================================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: Notice

This is the notice framework which enables Zeek to "notice" things which
are odd or potentially bad.  Decisions of the meaning of various notices
need to be done per site because Zeek does not ship with assumptions about
what is bad activity for sites.  More extensive documentation about using
the notice framework can be found in :doc:`/frameworks/notice`.

:Namespaces: GLOBAL, Notice
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`

Summary
~~~~~~~
Runtime Options
###############
========================================================================================== ======================================================================
:zeek:id:`Notice::alarmed_types`: :zeek:type:`set` :zeek:attr:`&redef`                     Alarmed notice types.
:zeek:id:`Notice::default_suppression_interval`: :zeek:type:`interval` :zeek:attr:`&redef` The notice framework is able to do automatic notice suppression by
                                                                                           utilizing the *identifier* field in :zeek:type:`Notice::Info` records.
:zeek:id:`Notice::emailed_types`: :zeek:type:`set` :zeek:attr:`&redef`                     Emailed notice types.
:zeek:id:`Notice::ignored_types`: :zeek:type:`set` :zeek:attr:`&redef`                     Ignored notice types.
:zeek:id:`Notice::mail_from`: :zeek:type:`string` :zeek:attr:`&redef`                      Address that emails will be from.
:zeek:id:`Notice::mail_subject_prefix`: :zeek:type:`string` :zeek:attr:`&redef`            Text string prefixed to the subject of all emails sent out.
:zeek:id:`Notice::not_suppressed_types`: :zeek:type:`set` :zeek:attr:`&redef`              Types that should be suppressed for the default suppression interval.
:zeek:id:`Notice::reply_to`: :zeek:type:`string` :zeek:attr:`&redef`                       Reply-to address used in outbound email.
:zeek:id:`Notice::sendmail`: :zeek:type:`string` :zeek:attr:`&redef`                       Local system sendmail program.
========================================================================================== ======================================================================

Redefinable Options
###################
===================================================================================== ====================================================================
:zeek:id:`Notice::mail_dest`: :zeek:type:`string` :zeek:attr:`&redef`                 Email address to send notices with the
                                                                                      :zeek:enum:`Notice::ACTION_EMAIL` action or to send bulk alarm logs
                                                                                      on rotation with :zeek:enum:`Notice::ACTION_ALARM`.
:zeek:id:`Notice::max_email_delay`: :zeek:type:`interval` :zeek:attr:`&redef`         The maximum amount of time a plugin can delay email from being sent.
:zeek:id:`Notice::type_suppression_intervals`: :zeek:type:`table` :zeek:attr:`&redef` This table can be used as a shorthand way to modify suppression
                                                                                      intervals for entire notice types.
===================================================================================== ====================================================================

Types
#####
================================================== =====================================================================
:zeek:type:`Notice::Action`: :zeek:type:`enum`     These are values representing actions that can be taken with notices.
:zeek:type:`Notice::ActionSet`: :zeek:type:`set`   Type that represents a set of actions.
:zeek:type:`Notice::FileInfo`: :zeek:type:`record` Contains a portion of :zeek:see:`fa_file` that's also contained in
                                                   :zeek:see:`Notice::Info`.
:zeek:type:`Notice::Info`: :zeek:type:`record`     The record type that is used for representing and logging notices.
:zeek:type:`Notice::Type`: :zeek:type:`enum`       Scripts creating new notices need to redef this enum to add their
                                                   own specific notice types which would then get used when they call
                                                   the :zeek:id:`NOTICE` function.
================================================== =====================================================================

Redefinitions
#############
======================================= =
:zeek:type:`Log::ID`: :zeek:type:`enum` 
======================================= =

Events
######
================================================================ =========================================================================
:zeek:id:`Notice::begin_suppression`: :zeek:type:`event`         This event is generated when a notice begins to be suppressed.
:zeek:id:`Notice::log_notice`: :zeek:type:`event`                This event can be handled to access the :zeek:type:`Notice::Info`
                                                                 record as it is sent on to the logging framework.
:zeek:id:`Notice::manager_begin_suppression`: :zeek:type:`event` This is an internal event that is used to broadcast the begin_suppression
                                                                 event over a cluster.
:zeek:id:`Notice::suppressed`: :zeek:type:`event`                This event is generated on each occurrence of an event being
                                                                 suppressed.
================================================================ =========================================================================

Hooks
#####
============================================ ==========================================================
:zeek:id:`Notice::notice`: :zeek:type:`hook` This is the event that is called as the entry point to the
                                             notice framework by the global :zeek:id:`NOTICE` function.
:zeek:id:`Notice::policy`: :zeek:type:`hook` The hook to modify notice handling.
============================================ ==========================================================

Functions
#########
=================================================================== ==========================================================================
:zeek:id:`NOTICE`: :zeek:type:`function`                            
:zeek:id:`Notice::apply_policy`: :zeek:type:`function`              This is an internal function to populate policy records.
:zeek:id:`Notice::create_file_info`: :zeek:type:`function`          Creates a record containing a subset of a full :zeek:see:`fa_file` record.
:zeek:id:`Notice::email_headers`: :zeek:type:`function`             Constructs mail headers to which an email body can be appended for
                                                                    sending with sendmail.
:zeek:id:`Notice::email_notice_to`: :zeek:type:`function`           Call this function to send a notice in an email.
:zeek:id:`Notice::is_being_suppressed`: :zeek:type:`function`       A function to determine if an event is supposed to be suppressed.
:zeek:id:`Notice::log_mailing_postprocessor`: :zeek:type:`function` A log postprocessing function that implements emailing the contents
                                                                    of a log upon rotation to any configured :zeek:id:`Notice::mail_dest`.
:zeek:id:`Notice::populate_file_info`: :zeek:type:`function`        Populates file-related fields in a notice info record.
:zeek:id:`Notice::populate_file_info2`: :zeek:type:`function`       Populates file-related fields in a notice info record.
=================================================================== ==========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Notice::alarmed_types

   :Type: :zeek:type:`set` [:zeek:type:`Notice::Type`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Alarmed notice types.

.. zeek:id:: Notice::default_suppression_interval

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 hr``

   The notice framework is able to do automatic notice suppression by
   utilizing the *identifier* field in :zeek:type:`Notice::Info` records.
   Set this to "0secs" to completely disable automated notice
   suppression.

.. zeek:id:: Notice::emailed_types

   :Type: :zeek:type:`set` [:zeek:type:`Notice::Type`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Emailed notice types.

.. zeek:id:: Notice::ignored_types

   :Type: :zeek:type:`set` [:zeek:type:`Notice::Type`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Ignored notice types.

.. zeek:id:: Notice::mail_from

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"Zeek <zeek@localhost>"``

   Address that emails will be from.
   
   Note that this is overridden by the ZeekControl MailFrom option.

.. zeek:id:: Notice::mail_subject_prefix

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"[Zeek]"``

   Text string prefixed to the subject of all emails sent out.
   
   Note that this is overridden by the ZeekControl MailSubjectPrefix
   option.

.. zeek:id:: Notice::not_suppressed_types

   :Type: :zeek:type:`set` [:zeek:type:`Notice::Type`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Types that should be suppressed for the default suppression interval.

.. zeek:id:: Notice::reply_to

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Reply-to address used in outbound email.

.. zeek:id:: Notice::sendmail

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"/usr/sbin/sendmail"``

   Local system sendmail program.
   
   Note that this is overridden by the ZeekControl SendMail option.

Redefinable Options
###################
.. zeek:id:: Notice::mail_dest

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Email address to send notices with the
   :zeek:enum:`Notice::ACTION_EMAIL` action or to send bulk alarm logs
   on rotation with :zeek:enum:`Notice::ACTION_ALARM`.
   
   Note that this is overridden by the ZeekControl MailTo option.

.. zeek:id:: Notice::max_email_delay

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``15.0 secs``

   The maximum amount of time a plugin can delay email from being sent.

.. zeek:id:: Notice::type_suppression_intervals

   :Type: :zeek:type:`table` [:zeek:type:`Notice::Type`] of :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   This table can be used as a shorthand way to modify suppression
   intervals for entire notice types.

Types
#####
.. zeek:type:: Notice::Action

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Notice::ACTION_NONE Notice::Action

         Indicates that there is no action to be taken.

      .. zeek:enum:: Notice::ACTION_LOG Notice::Action

         Indicates that the notice should be sent to the notice
         logging stream.

      .. zeek:enum:: Notice::ACTION_EMAIL Notice::Action

         Indicates that the notice should be sent to the email
         address(es) configured in the :zeek:id:`Notice::mail_dest`
         variable.

      .. zeek:enum:: Notice::ACTION_ALARM Notice::Action

         Indicates that the notice should be alarmed.  A readable
         ASCII version of the alarm log is emailed in bulk to the
         address(es) configured in :zeek:id:`Notice::mail_dest`.

      .. zeek:enum:: Notice::ACTION_EMAIL_ADMIN Notice::Action

         (present if :doc:`/scripts/base/frameworks/notice/actions/email_admin.zeek` is loaded)


         Indicate that the generated email should be addressed to the 
         appropriate email addresses as found by the
         :zeek:id:`Site::get_emails` function based on the relevant 
         address or addresses indicated in the notice.

      .. zeek:enum:: Notice::ACTION_PAGE Notice::Action

         (present if :doc:`/scripts/base/frameworks/notice/actions/page.zeek` is loaded)


         Indicates that the notice should be sent to the pager email
         address configured in the :zeek:id:`Notice::mail_page_dest`
         variable.

      .. zeek:enum:: Notice::ACTION_ADD_GEODATA Notice::Action

         (present if :doc:`/scripts/base/frameworks/notice/actions/add-geodata.zeek` is loaded)


         Indicates that the notice should have geodata added for the
         "remote" host.  :zeek:id:`Site::local_nets` must be defined
         in order for this to work.

      .. zeek:enum:: Notice::ACTION_DROP Notice::Action

         (present if :doc:`/scripts/policy/frameworks/notice/actions/drop.zeek` is loaded)


         Drops the address via :zeek:see:`NetControl::drop_address_catch_release`.

   These are values representing actions that can be taken with notices.

.. zeek:type:: Notice::ActionSet

   :Type: :zeek:type:`set` [:zeek:type:`Notice::Action`]

   Type that represents a set of actions.

.. zeek:type:: Notice::FileInfo

   :Type: :zeek:type:`record`

      fuid: :zeek:type:`string`
         File UID.

      desc: :zeek:type:`string`
         File description from e.g.
         :zeek:see:`Files::describe`.

      mime: :zeek:type:`string` :zeek:attr:`&optional`
         Strongest mime type match for file.

      cid: :zeek:type:`conn_id` :zeek:attr:`&optional`
         Connection tuple over which file is sent.

      cuid: :zeek:type:`string` :zeek:attr:`&optional`
         Connection UID over which file is sent.

   Contains a portion of :zeek:see:`fa_file` that's also contained in
   :zeek:see:`Notice::Info`.

.. zeek:type:: Notice::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log` :zeek:attr:`&optional`
         An absolute time indicating when the notice occurred,
         defaults to the current network time.

      uid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         A connection UID which uniquely identifies the endpoints
         concerned with the notice.

      id: :zeek:type:`conn_id` :zeek:attr:`&log` :zeek:attr:`&optional`
         A connection 4-tuple identifying the endpoints concerned
         with the notice.

      conn: :zeek:type:`connection` :zeek:attr:`&optional`
         A shorthand way of giving the uid and id to a notice.  The
         reference to the actual connection will be deleted after
         applying the notice policy.

      iconn: :zeek:type:`icmp_conn` :zeek:attr:`&optional`
         A shorthand way of giving the uid and id to a notice.  The
         reference to the actual connection will be deleted after
         applying the notice policy.

      f: :zeek:type:`fa_file` :zeek:attr:`&optional`
         A file record if the notice is related to a file.  The
         reference to the actual fa_file record will be deleted after
         applying the notice policy.

      fuid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         A file unique ID if this notice is related to a file.  If
         the *f* field is provided, this will be automatically filled
         out.

      file_mime_type: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         A mime type if the notice is related to a file.  If the *f*
         field is provided, this will be automatically filled out.

      file_desc: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Frequently files can be "described" to give a bit more
         context.  This field will typically be automatically filled
         out from an fa_file record.  For example, if a notice was
         related to a file over HTTP, the URL of the request would
         be shown.

      proto: :zeek:type:`transport_proto` :zeek:attr:`&log` :zeek:attr:`&optional`
         The transport protocol. Filled automatically when either
         *conn*, *iconn* or *p* is specified.

      note: :zeek:type:`Notice::Type` :zeek:attr:`&log`
         The :zeek:type:`Notice::Type` of the notice.

      msg: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The human readable message for the notice.

      sub: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The human readable sub-message.

      src: :zeek:type:`addr` :zeek:attr:`&log` :zeek:attr:`&optional`
         Source address, if we don't have a :zeek:type:`conn_id`.

      dst: :zeek:type:`addr` :zeek:attr:`&log` :zeek:attr:`&optional`
         Destination address.

      p: :zeek:type:`port` :zeek:attr:`&log` :zeek:attr:`&optional`
         Associated port, if we don't have a :zeek:type:`conn_id`.

      n: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
         Associated count, or perhaps a status code.

      peer_name: :zeek:type:`string` :zeek:attr:`&optional`
         Name of remote peer that raised this notice.

      peer_descr: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Textual description for the peer that raised this notice,
         including name, host address and port.

      actions: :zeek:type:`Notice::ActionSet` :zeek:attr:`&log` :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         The actions which have been applied to this notice.

      email_body_sections: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional`
         By adding chunks of text into this element, other scripts
         can expand on notices that are being emailed.  The normal
         way to add text is to extend the vector by handling the
         :zeek:id:`Notice::notice` event and modifying the notice in
         place.

      email_delay_tokens: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&optional`
         Adding a string "token" to this set will cause the notice
         framework's built-in emailing functionality to delay sending
         the email until either the token has been removed or the
         email has been delayed for :zeek:id:`Notice::max_email_delay`.

      identifier: :zeek:type:`string` :zeek:attr:`&optional`
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

      suppress_for: :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&default` = :zeek:see:`Notice::default_suppression_interval` :zeek:attr:`&optional`
         This field indicates the length of time that this
         unique notice should be suppressed.

      remote_location: :zeek:type:`geo_location` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/frameworks/notice/actions/add-geodata.zeek` is loaded)

         If GeoIP support is built in, notices can have geographic
         information attached to them.

      dropped: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/notice/actions/drop.zeek` is loaded)

         Indicate if the $src IP address was dropped and denied
         network access.

   The record type that is used for representing and logging notices.

.. zeek:type:: Notice::Type

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Notice::Tally Notice::Type

         Notice reporting a count of how often a notice occurred.

      .. zeek:enum:: Weird::Activity Notice::Type

         (present if :doc:`/scripts/base/frameworks/notice/weird.zeek` is loaded)


         Generic unusual but notice-worthy weird activity.

      .. zeek:enum:: Signatures::Sensitive_Signature Notice::Type

         (present if :doc:`/scripts/base/frameworks/signatures/main.zeek` is loaded)


         Generic notice type for notice-worthy signature matches.

      .. zeek:enum:: Signatures::Multiple_Signatures Notice::Type

         (present if :doc:`/scripts/base/frameworks/signatures/main.zeek` is loaded)


         Host has triggered many signatures on the same host.  The
         number of signatures is defined by the
         :zeek:id:`Signatures::vert_scan_thresholds` variable.

      .. zeek:enum:: Signatures::Multiple_Sig_Responders Notice::Type

         (present if :doc:`/scripts/base/frameworks/signatures/main.zeek` is loaded)


         Host has triggered the same signature on multiple hosts as
         defined by the :zeek:id:`Signatures::horiz_scan_thresholds`
         variable.

      .. zeek:enum:: Signatures::Count_Signature Notice::Type

         (present if :doc:`/scripts/base/frameworks/signatures/main.zeek` is loaded)


         The same signature has triggered multiple times for a host.
         The number of times the signature has been triggered is
         defined by the :zeek:id:`Signatures::count_thresholds`
         variable. To generate this notice, the
         :zeek:enum:`Signatures::SIG_COUNT_PER_RESP` action must be
         set for the signature.

      .. zeek:enum:: Signatures::Signature_Summary Notice::Type

         (present if :doc:`/scripts/base/frameworks/signatures/main.zeek` is loaded)


         Summarize the number of times a host triggered a signature.
         The interval between summaries is defined by the
         :zeek:id:`Signatures::summary_interval` variable.

      .. zeek:enum:: PacketFilter::Compile_Failure Notice::Type

         (present if :doc:`/scripts/base/frameworks/packet-filter/main.zeek` is loaded)


         This notice is generated if a packet filter cannot be compiled.

      .. zeek:enum:: PacketFilter::Install_Failure Notice::Type

         (present if :doc:`/scripts/base/frameworks/packet-filter/main.zeek` is loaded)


         Generated if a packet filter fails to install.

      .. zeek:enum:: PacketFilter::Too_Long_To_Compile_Filter Notice::Type

         (present if :doc:`/scripts/base/frameworks/packet-filter/main.zeek` is loaded)


         Generated when a notice takes too long to compile.

      .. zeek:enum:: PacketFilter::Dropped_Packets Notice::Type

         (present if :doc:`/scripts/base/frameworks/packet-filter/netstats.zeek` is loaded)


         Indicates packets were dropped by the packet filter.

      .. zeek:enum:: ProtocolDetector::Protocol_Found Notice::Type

         (present if :doc:`/scripts/policy/frameworks/dpd/detect-protocols.zeek` is loaded)


      .. zeek:enum:: ProtocolDetector::Server_Found Notice::Type

         (present if :doc:`/scripts/policy/frameworks/dpd/detect-protocols.zeek` is loaded)


      .. zeek:enum:: Intel::Notice Notice::Type

         (present if :doc:`/scripts/policy/frameworks/intel/do_notice.zeek` is loaded)


         This notice is generated when an intelligence
         indicator is denoted to be notice-worthy.

      .. zeek:enum:: TeamCymruMalwareHashRegistry::Match Notice::Type

         (present if :doc:`/scripts/policy/frameworks/files/detect-MHR.zeek` is loaded)


         The hash value of a file transferred over HTTP matched in the
         malware hash registry.

      .. zeek:enum:: PacketFilter::No_More_Conn_Shunts_Available Notice::Type

         (present if :doc:`/scripts/policy/frameworks/packet-filter/shunt.zeek` is loaded)


         Indicative that :zeek:id:`PacketFilter::max_bpf_shunts`
         connections are already being shunted with BPF filters and
         no more are allowed.

      .. zeek:enum:: PacketFilter::Cannot_BPF_Shunt_Conn Notice::Type

         (present if :doc:`/scripts/policy/frameworks/packet-filter/shunt.zeek` is loaded)


         Limitations in BPF make shunting some connections with BPF
         impossible.  This notice encompasses those various cases.

      .. zeek:enum:: Software::Software_Version_Change Notice::Type

         (present if :doc:`/scripts/policy/frameworks/software/version-changes.zeek` is loaded)


         For certain software, a version changing may matter.  In that
         case, this notice will be generated.  Software that matters
         if the version changes can be configured with the
         :zeek:id:`Software::interesting_version_changes` variable.

      .. zeek:enum:: Software::Vulnerable_Version Notice::Type

         (present if :doc:`/scripts/policy/frameworks/software/vulnerable.zeek` is loaded)


         Indicates that a vulnerable version of software was detected.

      .. zeek:enum:: CaptureLoss::Too_Much_Loss Notice::Type

         (present if :doc:`/scripts/policy/misc/capture-loss.zeek` is loaded)


         Report if the detected capture loss exceeds the percentage
         threshold.

      .. zeek:enum:: Traceroute::Detected Notice::Type

         (present if :doc:`/scripts/policy/misc/detect-traceroute/main.zeek` is loaded)


         Indicates that a host was seen running traceroutes.  For more
         detail about specific traceroutes that we run, refer to the
         traceroute.log.

      .. zeek:enum:: Scan::Address_Scan Notice::Type

         (present if :doc:`/scripts/policy/misc/scan.zeek` is loaded)


         Address scans detect that a host appears to be scanning some
         number of destinations on a single port. This notice is
         generated when more than :zeek:id:`Scan::addr_scan_threshold`
         unique hosts are seen over the previous
         :zeek:id:`Scan::addr_scan_interval` time range.

      .. zeek:enum:: Scan::Port_Scan Notice::Type

         (present if :doc:`/scripts/policy/misc/scan.zeek` is loaded)


         Port scans detect that an attacking host appears to be
         scanning a single victim host on several ports.  This notice
         is generated when an attacking host attempts to connect to
         :zeek:id:`Scan::port_scan_threshold`
         unique ports on a single host over the previous
         :zeek:id:`Scan::port_scan_interval` time range.

      .. zeek:enum:: Conn::Retransmission_Inconsistency Notice::Type

         (present if :doc:`/scripts/policy/protocols/conn/weirds.zeek` is loaded)


         Possible evasion; usually just chud.

      .. zeek:enum:: Conn::Content_Gap Notice::Type

         (present if :doc:`/scripts/policy/protocols/conn/weirds.zeek` is loaded)


         Data has sequence hole; perhaps due to filtering.

      .. zeek:enum:: DNS::External_Name Notice::Type

         (present if :doc:`/scripts/policy/protocols/dns/detect-external-names.zeek` is loaded)


         Raised when a non-local name is found to be pointing at a
         local host.  The :zeek:id:`Site::local_zones` variable
         **must** be set appropriately for this detection.

      .. zeek:enum:: FTP::Bruteforcing Notice::Type

         (present if :doc:`/scripts/policy/protocols/ftp/detect-bruteforcing.zeek` is loaded)


         Indicates a host bruteforcing FTP logins by watching for too
         many rejected usernames or failed passwords.

      .. zeek:enum:: FTP::Site_Exec_Success Notice::Type

         (present if :doc:`/scripts/policy/protocols/ftp/detect.zeek` is loaded)


         Indicates that a successful response to a "SITE EXEC" 
         command/arg pair was seen.

      .. zeek:enum:: HTTP::SQL_Injection_Attacker Notice::Type

         (present if :doc:`/scripts/policy/protocols/http/detect-sqli.zeek` is loaded)


         Indicates that a host performing SQL injection attacks was
         detected.

      .. zeek:enum:: HTTP::SQL_Injection_Victim Notice::Type

         (present if :doc:`/scripts/policy/protocols/http/detect-sqli.zeek` is loaded)


         Indicates that a host was seen to have SQL injection attacks
         against it.  This is tracked by IP address as opposed to
         hostname.

      .. zeek:enum:: SMTP::Blocklist_Error_Message Notice::Type

         (present if :doc:`/scripts/policy/protocols/smtp/blocklists.zeek` is loaded)


         An SMTP server sent a reply mentioning an SMTP block list.

      .. zeek:enum:: SMTP::Blocklist_Blocked_Host Notice::Type

         (present if :doc:`/scripts/policy/protocols/smtp/blocklists.zeek` is loaded)


         The originator's address is seen in the block list error message.
         This is useful to detect local hosts sending SPAM with a high
         positive rate.

      .. zeek:enum:: SMTP::Suspicious_Origination Notice::Type

         (present if :doc:`/scripts/policy/protocols/smtp/detect-suspicious-orig.zeek` is loaded)


      .. zeek:enum:: SSH::Password_Guessing Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssh/detect-bruteforcing.zeek` is loaded)


         Indicates that a host has been identified as crossing the
         :zeek:id:`SSH::password_guesses_limit` threshold with
         failed logins.

      .. zeek:enum:: SSH::Login_By_Password_Guesser Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssh/detect-bruteforcing.zeek` is loaded)


         Indicates that a host previously identified as a "password
         guesser" has now had a successful login
         attempt. This is not currently implemented.

      .. zeek:enum:: SSH::Watched_Country_Login Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssh/geo-data.zeek` is loaded)


         If an SSH login is seen to or from a "watched" country based
         on the :zeek:id:`SSH::watched_countries` variable then this
         notice will be generated.

      .. zeek:enum:: SSH::Interesting_Hostname_Login Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssh/interesting-hostnames.zeek` is loaded)


         Generated if a login originates or responds with a host where
         the reverse hostname lookup resolves to a name matched by the
         :zeek:id:`SSH::interesting_hostnames` regular expression.

      .. zeek:enum:: SSL::Certificate_Expired Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/expiring-certs.zeek` is loaded)


         Indicates that a certificate's NotValidAfter date has lapsed
         and the certificate is now invalid.

      .. zeek:enum:: SSL::Certificate_Expires_Soon Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/expiring-certs.zeek` is loaded)


         Indicates that a certificate is going to expire within 
         :zeek:id:`SSL::notify_when_cert_expiring_in`.

      .. zeek:enum:: SSL::Certificate_Not_Valid_Yet Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/expiring-certs.zeek` is loaded)


         Indicates that a certificate's NotValidBefore date is future
         dated.

      .. zeek:enum:: Heartbleed::SSL_Heartbeat_Attack Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/heartbleed.zeek` is loaded)


         Indicates that a host performed a heartbleed attack or scan.

      .. zeek:enum:: Heartbleed::SSL_Heartbeat_Attack_Success Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/heartbleed.zeek` is loaded)


         Indicates that a host performing a heartbleed attack was probably successful.

      .. zeek:enum:: Heartbleed::SSL_Heartbeat_Odd_Length Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/heartbleed.zeek` is loaded)


         Indicates we saw heartbeat requests with odd length. Probably an attack or scan.

      .. zeek:enum:: Heartbleed::SSL_Heartbeat_Many_Requests Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/heartbleed.zeek` is loaded)


         Indicates we saw many heartbeat requests without a reply. Might be an attack.

      .. zeek:enum:: SSL::Invalid_Server_Cert Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/validate-certs.zeek` is loaded)


         This notice indicates that the result of validating the
         certificate along with its full certificate chain was
         invalid.

      .. zeek:enum:: SSL::Invalid_Ocsp_Response Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/validate-ocsp.zeek` is loaded)


         This indicates that the OCSP response was not deemed
         to be valid.

      .. zeek:enum:: SSL::Weak_Key Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/weak-keys.zeek` is loaded)


         Indicates that a server is using a potentially unsafe key.

      .. zeek:enum:: SSL::Old_Version Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/weak-keys.zeek` is loaded)


         Indicates that a server is using a potentially unsafe version

      .. zeek:enum:: SSL::Weak_Cipher Notice::Type

         (present if :doc:`/scripts/policy/protocols/ssl/weak-keys.zeek` is loaded)


         Indicates that a server is using a potentially unsafe cipher

      .. zeek:enum:: ZeekygenExample::Zeekygen_One Notice::Type

         (present if :doc:`/scripts/zeekygen/example.zeek` is loaded)


         Any number of this type of comment
         will document "Zeekygen_One".

      .. zeek:enum:: ZeekygenExample::Zeekygen_Two Notice::Type

         (present if :doc:`/scripts/zeekygen/example.zeek` is loaded)


         Any number of this type of comment
         will document "ZEEKYGEN_TWO".

      .. zeek:enum:: ZeekygenExample::Zeekygen_Three Notice::Type

         (present if :doc:`/scripts/zeekygen/example.zeek` is loaded)


      .. zeek:enum:: ZeekygenExample::Zeekygen_Four Notice::Type

         (present if :doc:`/scripts/zeekygen/example.zeek` is loaded)


         Omitting comments is fine, and so is mixing ``##`` and ``##<``, but
         it's probably best to use only one style consistently.

   Scripts creating new notices need to redef this enum to add their
   own specific notice types which would then get used when they call
   the :zeek:id:`NOTICE` function.  The convention is to give a general
   category along with the specific notice separating words with
   underscores and using leading capitals on each word except for
   abbreviations which are kept in all capitals. For example,
   SSH::Password_Guessing is for hosts that have crossed a threshold of
   failed SSH logins.

Events
######
.. zeek:id:: Notice::begin_suppression

   :Type: :zeek:type:`event` (ts: :zeek:type:`time`, suppress_for: :zeek:type:`interval`, note: :zeek:type:`Notice::Type`, identifier: :zeek:type:`string`)

   This event is generated when a notice begins to be suppressed.
   

   :ts: time indicating then when the notice to be suppressed occured.
   

   :suppress_for: length of time that this notice should be suppressed.
   

   :note: The :zeek:type:`Notice::Type` of the notice.
   

   :identifier: The identifier string of the notice that should be suppressed.

.. zeek:id:: Notice::log_notice

   :Type: :zeek:type:`event` (rec: :zeek:type:`Notice::Info`)

   This event can be handled to access the :zeek:type:`Notice::Info`
   record as it is sent on to the logging framework.
   

   :rec: The record containing notice data before it is logged.

.. zeek:id:: Notice::manager_begin_suppression

   :Type: :zeek:type:`event` (ts: :zeek:type:`time`, suppress_for: :zeek:type:`interval`, note: :zeek:type:`Notice::Type`, identifier: :zeek:type:`string`)

   This is an internal event that is used to broadcast the begin_suppression
   event over a cluster.
   

   :ts: time indicating then when the notice to be suppressed occured.
   

   :suppress_for: length of time that this notice should be suppressed.
   

   :note: The :zeek:type:`Notice::Type` of the notice.
   

   :identifier: The identifier string of the notice that should be suppressed.

.. zeek:id:: Notice::suppressed

   :Type: :zeek:type:`event` (n: :zeek:type:`Notice::Info`)

   This event is generated on each occurrence of an event being
   suppressed.
   

   :n: The record containing notice data regarding the notice type
      being suppressed.

Hooks
#####
.. zeek:id:: Notice::notice

   :Type: :zeek:type:`hook` (n: :zeek:type:`Notice::Info`) : :zeek:type:`bool`

   This is the event that is called as the entry point to the
   notice framework by the global :zeek:id:`NOTICE` function. By the
   time this event is generated, default values have already been
   filled out in the :zeek:type:`Notice::Info` record and the notice
   policy has also been applied.
   

   :n: The record containing notice data.

.. zeek:id:: Notice::policy

   :Type: :zeek:type:`hook` (n: :zeek:type:`Notice::Info`) : :zeek:type:`bool`

   The hook to modify notice handling.

Functions
#########
.. zeek:id:: NOTICE

   :Type: :zeek:type:`function` (n: :zeek:type:`Notice::Info`) : :zeek:type:`void`


.. zeek:id:: Notice::apply_policy

   :Type: :zeek:type:`function` (n: :zeek:type:`Notice::Info`) : :zeek:type:`void`

   This is an internal function to populate policy records.

.. zeek:id:: Notice::create_file_info

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`) : :zeek:type:`Notice::FileInfo`

   Creates a record containing a subset of a full :zeek:see:`fa_file` record.
   

   :f: record containing metadata about a file.
   

   :returns: record containing a subset of fields copied from *f*.

.. zeek:id:: Notice::email_headers

   :Type: :zeek:type:`function` (subject_desc: :zeek:type:`string`, dest: :zeek:type:`string`) : :zeek:type:`string`

   Constructs mail headers to which an email body can be appended for
   sending with sendmail.
   

   :subject_desc: a subject string to use for the mail.
   

   :dest: recipient string to use for the mail.
   

   :returns: a string of mail headers to which an email body can be
            appended.

.. zeek:id:: Notice::email_notice_to

   :Type: :zeek:type:`function` (n: :zeek:type:`Notice::Info`, dest: :zeek:type:`string`, extend: :zeek:type:`bool`) : :zeek:type:`void`

   Call this function to send a notice in an email.  It is already used
   by default with the built in :zeek:enum:`Notice::ACTION_EMAIL` and
   :zeek:enum:`Notice::ACTION_PAGE` actions.
   

   :n: The record of notice data to email.
   

   :dest: The intended recipient of the notice email.
   

   :extend: Whether to extend the email using the
           ``email_body_sections`` field of *n*.

.. zeek:id:: Notice::is_being_suppressed

   :Type: :zeek:type:`function` (n: :zeek:type:`Notice::Info`) : :zeek:type:`bool`

   A function to determine if an event is supposed to be suppressed.
   

   :n: The record containing the notice in question.

.. zeek:id:: Notice::log_mailing_postprocessor

   :Type: :zeek:type:`function` (info: :zeek:type:`Log::RotationInfo`) : :zeek:type:`bool`

   A log postprocessing function that implements emailing the contents
   of a log upon rotation to any configured :zeek:id:`Notice::mail_dest`.
   The rotated log is removed upon being sent.
   

   :info: A record containing the rotated log file information.
   

   :returns: True.

.. zeek:id:: Notice::populate_file_info

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`, n: :zeek:type:`Notice::Info`) : :zeek:type:`void`

   Populates file-related fields in a notice info record.
   

   :f: record containing metadata about a file.
   

   :n: a notice record that needs file-related fields populated.

.. zeek:id:: Notice::populate_file_info2

   :Type: :zeek:type:`function` (fi: :zeek:type:`Notice::FileInfo`, n: :zeek:type:`Notice::Info`) : :zeek:type:`void`

   Populates file-related fields in a notice info record.
   

   :fi: record containing metadata about a file.
   

   :n: a notice record that needs file-related fields populated.


