:tocdepth: 3

base/protocols/ftp/main.zeek
============================
.. zeek:namespace:: FTP

The logging this script does is primarily focused on logging FTP commands
along with metadata.  For example, if files are transferred, the argument
will take on the full path that the client is at along with the requested
file name.

:Namespace: FTP
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/notice/weird.zeek </scripts/base/frameworks/notice/weird.zeek>`, :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/ftp/info.zeek </scripts/base/protocols/ftp/info.zeek>`, :doc:`base/protocols/ftp/utils-commands.zeek </scripts/base/protocols/ftp/utils-commands.zeek>`, :doc:`base/protocols/ftp/utils.zeek </scripts/base/protocols/ftp/utils.zeek>`, :doc:`base/utils/addrs.zeek </scripts/base/utils/addrs.zeek>`, :doc:`base/utils/numbers.zeek </scripts/base/utils/numbers.zeek>`, :doc:`base/utils/paths.zeek </scripts/base/utils/paths.zeek>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================ ======================================================================
:zeek:id:`FTP::guest_ids`: :zeek:type:`set` :zeek:attr:`&redef`              User IDs that can be considered "anonymous".
:zeek:id:`FTP::logged_commands`: :zeek:type:`set` :zeek:attr:`&redef`        List of commands that should have their command/response pairs logged.
:zeek:id:`FTP::max_arg_length`: :zeek:type:`count` :zeek:attr:`&redef`       Truncate the arg field in the log to that many bytes to avoid
                                                                             excessive logging volume.
:zeek:id:`FTP::max_password_length`: :zeek:type:`count` :zeek:attr:`&redef`  Truncate the password field in the log to that many bytes to avoid
                                                                             excessive logging volume as this values is replicated in each
                                                                             of the entries related to an FTP session.
:zeek:id:`FTP::max_pending_commands`: :zeek:type:`count` :zeek:attr:`&redef` Allow a client to send this many commands before the server
                                                                             sends a reply.
:zeek:id:`FTP::max_reply_msg_length`: :zeek:type:`count` :zeek:attr:`&redef` Truncate the reply_msg field in the log to that many bytes to avoid
                                                                             excessive logging volume.
:zeek:id:`FTP::max_user_length`: :zeek:type:`count` :zeek:attr:`&redef`      Truncate the user field in the log to that many bytes to avoid
                                                                             excessive logging volume as this values is replicated in each
                                                                             of the entries related to an FTP session.
============================================================================ ======================================================================

Redefinable Options
###################
=========================================================== =========================
:zeek:id:`FTP::ports`: :zeek:type:`set` :zeek:attr:`&redef` Well-known ports for FTP.
=========================================================== =========================

Types
#####
================================================ ===============================================
:zeek:type:`FTP::ReplyCode`: :zeek:type:`record` This record is to hold a parsed FTP reply code.
================================================ ===============================================

Redefinitions
#############
============================================ ========================================================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      The FTP protocol logging stream identifier.

                                             * :zeek:enum:`FTP::LOG`
:zeek:type:`connection`: :zeek:type:`record`

                                             :New Fields: :zeek:type:`connection`

                                               ftp: :zeek:type:`FTP::Info` :zeek:attr:`&optional`

                                               ftp_data_reuse: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
============================================ ========================================================================================

Events
######
=========================================== ==============================================================
:zeek:id:`FTP::log_ftp`: :zeek:type:`event` Event that can be handled to access the :zeek:type:`FTP::Info`
                                            record as it is sent on to the logging framework.
=========================================== ==============================================================

Hooks
#####
============================================================ =============================================
:zeek:id:`FTP::finalize_ftp`: :zeek:type:`Conn::RemovalHook` FTP finalization hook.
:zeek:id:`FTP::finalize_ftp_data`: :zeek:type:`hook`         FTP data finalization hook.
:zeek:id:`FTP::log_policy`: :zeek:type:`Log::PolicyHook`     A default logging policy hook for the stream.
============================================================ =============================================

Functions
#########
=========================================================== =====================================================================
:zeek:id:`FTP::parse_ftp_reply_code`: :zeek:type:`function` Parse FTP reply codes into the three constituent single digit values.
=========================================================== =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: FTP::guest_ids
   :source-code: base/protocols/ftp/main.zeek 35 35

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            "guest",
            "anonymous",
            "ftpuser",
            "ftp"
         }


   User IDs that can be considered "anonymous".

.. zeek:id:: FTP::logged_commands
   :source-code: base/protocols/ftp/main.zeek 29 29

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            "ACCT",
            "DELE",
            "APPE",
            "RETR",
            "PORT",
            "STOR",
            "EPRT",
            "PASV",
            "STOU",
            "EPSV"
         }


   List of commands that should have their command/response pairs logged.

.. zeek:id:: FTP::max_arg_length
   :source-code: base/protocols/ftp/main.zeek 76 76

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``4096``

   Truncate the arg field in the log to that many bytes to avoid
   excessive logging volume.

.. zeek:id:: FTP::max_password_length
   :source-code: base/protocols/ftp/main.zeek 72 72

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``128``

   Truncate the password field in the log to that many bytes to avoid
   excessive logging volume as this values is replicated in each
   of the entries related to an FTP session.

.. zeek:id:: FTP::max_pending_commands
   :source-code: base/protocols/ftp/main.zeek 62 62

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``20``

   Allow a client to send this many commands before the server
   sends a reply. If this value is exceeded a weird named
   FTP_too_many_pending_commands is logged for the connection.

.. zeek:id:: FTP::max_reply_msg_length
   :source-code: base/protocols/ftp/main.zeek 80 80

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``4096``

   Truncate the reply_msg field in the log to that many bytes to avoid
   excessive logging volume.

.. zeek:id:: FTP::max_user_length
   :source-code: base/protocols/ftp/main.zeek 67 67

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``128``

   Truncate the user field in the log to that many bytes to avoid
   excessive logging volume as this values is replicated in each
   of the entries related to an FTP session.

Redefinable Options
###################
.. zeek:id:: FTP::ports
   :source-code: base/protocols/ftp/main.zeek 23 23

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            2811/tcp,
            21/tcp
         }


   Well-known ports for FTP.

Types
#####
.. zeek:type:: FTP::ReplyCode
   :source-code: base/protocols/ftp/main.zeek 39 43

   :Type: :zeek:type:`record`


   .. zeek:field:: x :zeek:type:`count`


   .. zeek:field:: y :zeek:type:`count`


   .. zeek:field:: z :zeek:type:`count`


   This record is to hold a parsed FTP reply code.  For example, for the
   201 status code, the digits would be parsed as: x->2, y->0, z->1.

Events
######
.. zeek:id:: FTP::log_ftp
   :source-code: base/protocols/ftp/main.zeek 50 50

   :Type: :zeek:type:`event` (rec: :zeek:type:`FTP::Info`)

   Event that can be handled to access the :zeek:type:`FTP::Info`
   record as it is sent on to the logging framework.

Hooks
#####
.. zeek:id:: FTP::finalize_ftp
   :source-code: base/protocols/ftp/main.zeek 479 488

   :Type: :zeek:type:`Conn::RemovalHook`

   FTP finalization hook.  Remaining FTP info may get logged when it's called.

.. zeek:id:: FTP::finalize_ftp_data
   :source-code: base/protocols/ftp/main.zeek 466 476

   :Type: :zeek:type:`hook` (c: :zeek:type:`connection`) : :zeek:type:`bool`

   FTP data finalization hook.  Expected FTP data channel state may
   get purged when called.

.. zeek:id:: FTP::log_policy
   :source-code: base/protocols/ftp/main.zeek 26 26

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.

Functions
#########
.. zeek:id:: FTP::parse_ftp_reply_code
   :source-code: base/protocols/ftp/main.zeek 141 154

   :Type: :zeek:type:`function` (code: :zeek:type:`count`) : :zeek:type:`FTP::ReplyCode`

   Parse FTP reply codes into the three constituent single digit values.


