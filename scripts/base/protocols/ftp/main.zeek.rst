:tocdepth: 3

base/protocols/ftp/main.zeek
============================
.. bro:namespace:: FTP

The logging this script does is primarily focused on logging FTP commands
along with metadata.  For example, if files are transferred, the argument
will take on the full path that the client is at along with the requested
file name.

:Namespace: FTP
:Imports: :doc:`base/protocols/ftp/info.zeek </scripts/base/protocols/ftp/info.zeek>`, :doc:`base/protocols/ftp/utils-commands.zeek </scripts/base/protocols/ftp/utils-commands.zeek>`, :doc:`base/protocols/ftp/utils.zeek </scripts/base/protocols/ftp/utils.zeek>`, :doc:`base/utils/addrs.zeek </scripts/base/utils/addrs.zeek>`, :doc:`base/utils/numbers.zeek </scripts/base/utils/numbers.zeek>`, :doc:`base/utils/paths.zeek </scripts/base/utils/paths.zeek>`

Summary
~~~~~~~
Runtime Options
###############
================================================================== ======================================================================
:bro:id:`FTP::guest_ids`: :bro:type:`set` :bro:attr:`&redef`       User IDs that can be considered "anonymous".
:bro:id:`FTP::logged_commands`: :bro:type:`set` :bro:attr:`&redef` List of commands that should have their command/response pairs logged.
================================================================== ======================================================================

Types
#####
============================================== ===============================================
:bro:type:`FTP::ReplyCode`: :bro:type:`record` This record is to hold a parsed FTP reply code.
============================================== ===============================================

Redefinitions
#############
================================================================= ===========================================
:bro:type:`Log::ID`: :bro:type:`enum`                             The FTP protocol logging stream identifier.
:bro:type:`connection`: :bro:type:`record`                        
:bro:id:`likely_server_ports`: :bro:type:`set` :bro:attr:`&redef` 
================================================================= ===========================================

Events
######
========================================= =============================================================
:bro:id:`FTP::log_ftp`: :bro:type:`event` Event that can be handled to access the :bro:type:`FTP::Info`
                                          record as it is sent on to the logging framework.
========================================= =============================================================

Functions
#########
========================================================= =====================================================================
:bro:id:`FTP::parse_ftp_reply_code`: :bro:type:`function` Parse FTP reply codes into the three constituent single digit values.
========================================================= =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: FTP::guest_ids

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         "ftpuser",
         "ftp",
         "guest",
         "anonymous"
      }

   User IDs that can be considered "anonymous".

.. bro:id:: FTP::logged_commands

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         "RETR",
         "EPSV",
         "EPRT",
         "DELE",
         "PORT",
         "PASV",
         "STOR",
         "APPE",
         "STOU",
         "ACCT"
      }

   List of commands that should have their command/response pairs logged.

Types
#####
.. bro:type:: FTP::ReplyCode

   :Type: :bro:type:`record`

      x: :bro:type:`count`

      y: :bro:type:`count`

      z: :bro:type:`count`

   This record is to hold a parsed FTP reply code.  For example, for the
   201 status code, the digits would be parsed as: x->2, y->0, z->1.

Events
######
.. bro:id:: FTP::log_ftp

   :Type: :bro:type:`event` (rec: :bro:type:`FTP::Info`)

   Event that can be handled to access the :bro:type:`FTP::Info`
   record as it is sent on to the logging framework.

Functions
#########
.. bro:id:: FTP::parse_ftp_reply_code

   :Type: :bro:type:`function` (code: :bro:type:`count`) : :bro:type:`FTP::ReplyCode`

   Parse FTP reply codes into the three constituent single digit values.


