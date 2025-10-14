:tocdepth: 3

base/protocols/mysql/main.zeek
==============================
.. zeek:namespace:: MySQL

Implements base functionality for MySQL analysis. Generates the mysql.log file.

:Namespace: MySQL
:Imports: :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/mysql/consts.zeek </scripts/base/protocols/mysql/consts.zeek>`

Summary
~~~~~~~
Types
#####
============================================= =
:zeek:type:`MySQL::Info`: :zeek:type:`record` 
============================================= =

Redefinitions
#############
============================================ ========================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      
                                             
                                             * :zeek:enum:`mysql::LOG`
:zeek:type:`connection`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`connection`
                                             
                                               mysql: :zeek:type:`MySQL::Info` :zeek:attr:`&optional`
============================================ ========================================================

Events
######
=============================================== =====================================================================
:zeek:id:`MySQL::log_mysql`: :zeek:type:`event` Event that can be handled to access the MySQL record as it is sent on
                                                to the logging framework.
=============================================== =====================================================================

Hooks
#####
================================================================ ========================
:zeek:id:`MySQL::finalize_mysql`: :zeek:type:`Conn::RemovalHook` MySQL finalization hook.
:zeek:id:`MySQL::log_policy`: :zeek:type:`Log::PolicyHook`       
================================================================ ========================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: MySQL::Info
   :source-code: base/protocols/mysql/main.zeek 13 30

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp for when the event happened.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      cmd: :zeek:type:`string` :zeek:attr:`&log`
         The command that was issued

      arg: :zeek:type:`string` :zeek:attr:`&log`
         The argument issued to the command

      success: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`
         Did the server tell us that the command succeeded?

      rows: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
         The number of affected rows, if any

      response: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Server message, if any


Events
######
.. zeek:id:: MySQL::log_mysql
   :source-code: base/protocols/mysql/main.zeek 34 34

   :Type: :zeek:type:`event` (rec: :zeek:type:`MySQL::Info`)

   Event that can be handled to access the MySQL record as it is sent on
   to the logging framework.

Hooks
#####
.. zeek:id:: MySQL::finalize_mysql
   :source-code: base/protocols/mysql/main.zeek 152 159

   :Type: :zeek:type:`Conn::RemovalHook`

   MySQL finalization hook.  Remaining MySQL info may get logged when it's called.

.. zeek:id:: MySQL::log_policy
   :source-code: base/protocols/mysql/main.zeek 11 11

   :Type: :zeek:type:`Log::PolicyHook`



