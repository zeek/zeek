:tocdepth: 3

base/protocols/irc/main.zeek
============================
.. zeek:namespace:: IRC

Implements the core IRC analysis support.  The logging model is to log
IRC commands along with the associated response and some additional
metadata about the connection if it's available.

:Namespace: IRC

Summary
~~~~~~~
Redefinable Options
###################
=========================================================== =========================
:zeek:id:`IRC::ports`: :zeek:type:`set` :zeek:attr:`&redef` Well-known ports for IRC.
=========================================================== =========================

Types
#####
=========================================== =
:zeek:type:`IRC::Info`: :zeek:type:`record` 
=========================================== =

Redefinitions
#############
============================================ ====================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      
                                             
                                             * :zeek:enum:`IRC::LOG`
:zeek:type:`connection`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`connection`
                                             
                                               irc: :zeek:type:`IRC::Info` :zeek:attr:`&optional`
                                                 IRC session information.
============================================ ====================================================

Events
######
=========================================== ===================================================================
:zeek:id:`IRC::irc_log`: :zeek:type:`event` Event that can be handled to access the IRC record as it is sent on
                                            to the logging framework.
=========================================== ===================================================================

Hooks
#####
======================================================== =
:zeek:id:`IRC::log_policy`: :zeek:type:`Log::PolicyHook` 
======================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: IRC::ports
   :source-code: base/protocols/irc/main.zeek 11 11

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            6666/tcp,
            6669/tcp,
            6668/tcp,
            6667/tcp
         }


   Well-known ports for IRC.

Types
#####
.. zeek:type:: IRC::Info
   :source-code: base/protocols/irc/main.zeek 15 33

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp when the command was seen.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique ID for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports.


   .. zeek:field:: nick :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Nickname given for the connection.


   .. zeek:field:: user :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Username given for the connection.


   .. zeek:field:: command :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Command given by the client.


   .. zeek:field:: value :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Value for the command given by the client.


   .. zeek:field:: addl :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Any additional data for the command.


   .. zeek:field:: dcc_file_name :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/irc/dcc-send.zeek` is loaded)

      DCC filename requested.


   .. zeek:field:: dcc_file_size :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/irc/dcc-send.zeek` is loaded)

      Size of the DCC transfer as indicated by the sender.


   .. zeek:field:: dcc_mime_type :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/irc/dcc-send.zeek` is loaded)

      Sniffed mime type of the file.


   .. zeek:field:: fuid :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/irc/files.zeek` is loaded)

      File unique ID.



Events
######
.. zeek:id:: IRC::irc_log
   :source-code: base/protocols/irc/main.zeek 37 37

   :Type: :zeek:type:`event` (rec: :zeek:type:`IRC::Info`)

   Event that can be handled to access the IRC record as it is sent on
   to the logging framework.

Hooks
#####
.. zeek:id:: IRC::log_policy
   :source-code: base/protocols/irc/main.zeek 13 13

   :Type: :zeek:type:`Log::PolicyHook`



